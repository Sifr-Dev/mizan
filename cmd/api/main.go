package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohamedsalahi/GO_DB/config"
	"github.com/mohamedsalahi/GO_DB/internal/delivery/handler"
	"github.com/mohamedsalahi/GO_DB/internal/infra/auth"
	"github.com/mohamedsalahi/GO_DB/internal/infra/db"
	"github.com/mohamedsalahi/GO_DB/internal/infra/logger"
	"github.com/mohamedsalahi/GO_DB/internal/repository"
	"github.com/mohamedsalahi/GO_DB/internal/usecase"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("invalid config: %v", err))
	}

	logger.SetupLogger(cfg.App.Env, cfg.Log.Level)
	slog.Info("starting application",
		slog.String("name", cfg.App.Name),
		slog.String("version", cfg.App.Version),
		slog.String("env", cfg.App.Env),
	)
	slog.Info("administrator provisioning is explicit; use `go run ./cmd/admin` when needed")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPool, err := db.NewPostgresPool(ctx, cfg)
	if err != nil {
		slog.Error("failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer dbPool.Close()

	rdb, err := db.NewRedisClient(ctx, cfg)
	if err != nil {
		slog.Error("failed to connect to redis", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer rdb.Close()

	tokenMgr := auth.NewTokenManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessExpiration,
		cfg.JWT.RefreshExpiration,
	)

	userRepo := repository.NewUserRepo(dbPool)
	taskRepo := repository.NewTaskRepo(dbPool)

	userService := usecase.NewUserService(userRepo, tokenMgr)
	taskService := usecase.NewTaskService(taskRepo, userRepo)
	adminService := usecase.NewAdminService(userRepo, taskRepo)

	// Check for frontend dist directory (for production builds).
	frontendDir := "frontend/dist"
	if _, err := os.Stat(frontendDir); os.IsNotExist(err) {
		frontendDir = ""
	}

	router := handler.NewRouter(&handler.Dependencies{
		UserService:  userService,
		TaskService:  taskService,
		AdminService: adminService,
		TokenMgr:     tokenMgr,
		RedisClient:  rdb,
		FrontendDir:  frontendDir,
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.HTTP.Port),
		Handler:      router,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	<-shutdown
	slog.Info("shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced to shutdown", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
