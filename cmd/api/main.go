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

	"github.com/Sifr-Dev/mizan/config"
	"github.com/Sifr-Dev/mizan/internal/delivery/handler"
	"github.com/Sifr-Dev/mizan/internal/infra/auth"
	"github.com/Sifr-Dev/mizan/internal/infra/db"
	"github.com/Sifr-Dev/mizan/internal/infra/logger"
	"github.com/Sifr-Dev/mizan/internal/repository"
	"github.com/Sifr-Dev/mizan/internal/usecase"
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
		auth.NewRedisSessionStore(rdb),
		auth.WithIssuer(cfg.JWT.Issuer),
		auth.WithAudience(cfg.JWT.Audience),
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

	allowedOrigins, err := cfg.CORSOrigins()
	if err != nil {
		panic(fmt.Sprintf("invalid CORS configuration: %v", err))
	}
	trustedProxies, err := cfg.TrustedProxyCIDRs()
	if err != nil {
		panic(fmt.Sprintf("invalid trusted proxy configuration: %v", err))
	}
	sameSite, err := cfg.SameSiteMode()
	if err != nil {
		panic(fmt.Sprintf("invalid cookie configuration: %v", err))
	}

	router := handler.NewRouter(&handler.Dependencies{
		UserService:       userService,
		TaskService:       taskService,
		AdminService:      adminService,
		TokenMgr:          tokenMgr,
		RedisClient:       rdb,
		FrontendDir:       frontendDir,
		AllowedOrigins:    allowedOrigins,
		TrustedProxyCIDRs: trustedProxies,
		RateLimitMax:      cfg.RateLimit.MaxRequests,
		RateLimitWindow:   cfg.RateLimit.Window,
		RateLimitFailOpen: cfg.RateLimit.FailOpen,
		RateLimitScope:    cfg.RateLimit.Scope,
		MaxBodyBytes:      cfg.Request.MaxBodyBytes,
		RefreshCookie: handler.CookieConfig{
			Name:           cfg.Auth.CookieName,
			Path:           cfg.Auth.CookiePath,
			Secure:         cfg.Auth.CookieSecure,
			SameSite:       sameSite,
			MaxAge:         int(cfg.JWT.RefreshExpiration.Seconds()),
			AllowedOrigins: allowedOrigins,
		},
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
