package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mohamedsalahi/GO_DB/config"
	"github.com/mohamedsalahi/GO_DB/internal/infra/db"
	"github.com/mohamedsalahi/GO_DB/internal/repository"
	"github.com/mohamedsalahi/GO_DB/internal/usecase"
)

func main() {
	adminConfig, err := config.LoadAdminConfig()
	if err != nil {
		slog.Error("invalid administrator provisioning configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbConfig := &config.Config{DB: config.DBConfig{
		URL:      adminConfig.DatabaseURL,
		MaxConns: 1,
	}}
	pool, err := db.NewPostgresPool(ctx, dbConfig)
	if err != nil {
		slog.Error("failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	userRepo := repository.NewUserRepo(pool)
	admin, err := usecase.ProvisionAdmin(ctx, userRepo, adminConfig.Email, adminConfig.Name, adminConfig.Password)
	if err != nil {
		slog.Error("administrator provisioning failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	fmt.Printf("administrator created: %s\n", admin.Email)
}
