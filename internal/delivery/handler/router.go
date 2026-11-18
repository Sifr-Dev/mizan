package handler

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Sifr-Dev/mizan/internal/delivery/handler/middleware"
	"github.com/Sifr-Dev/mizan/internal/domain"
	"github.com/Sifr-Dev/mizan/internal/infra/auth"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"
)

type Dependencies struct {
	UserService  domain.UserService
	TaskService  domain.TaskService
	AdminService domain.AdminService
	TokenMgr     *auth.TokenManager
	RedisClient  *redis.Client
	FrontendDir  string // path to built frontend dist, empty = no frontend

	AllowedOrigins    []string
	TrustedProxyCIDRs []*net.IPNet
	RateLimitMax      int
	RateLimitWindow   time.Duration
	RateLimitFailOpen bool
	RateLimitScope    string
	MaxBodyBytes      int64
	RefreshCookie     CookieConfig
}

func NewRouter(deps *Dependencies) http.Handler {
	r := chi.NewRouter()

	// Global middleware. Forwarding headers are ignored unless the immediate
	// peer is explicitly listed as a trusted proxy.
	r.Use(middleware.ClientIPMiddleware(deps.TrustedProxyCIDRs))
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(middleware.RequestLogger)

	// Install CORS only for a non-empty, validated exact-origin allowlist.
	// go-chi/cors treats an empty origin list as allow-all, so omitting the
	// middleware is what actually enforces same-origin-only behavior.
	if len(deps.AllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   deps.AllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			ExposedHeaders:   []string{"Link", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// Health checks are intentionally outside the API rate-limit scope.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/api/v1", func(api chi.Router) {
		if deps.RedisClient != nil {
			rateLimiter := middleware.NewRateLimiter(
				deps.RedisClient,
				deps.RateLimitMax,
				deps.RateLimitWindow,
				middleware.WithRateLimitFailOpen(deps.RateLimitFailOpen),
				middleware.WithRateLimitScope(deps.RateLimitScope),
			)
			api.Use(rateLimiter.Middleware)
		}

		// Authentication routes (public).
		api.Route("/auth", func(authRoutes chi.Router) {
			userHandler := NewUserHandler(
				deps.UserService,
				WithUserBodyLimit(deps.MaxBodyBytes),
				WithRefreshCookie(deps.RefreshCookie),
			)
			authRoutes.Post("/register", userHandler.Register)
			authRoutes.Post("/login", userHandler.Login)
			authRoutes.Post("/refresh", userHandler.Refresh)
			authRoutes.Post("/logout", userHandler.Logout)
		})

		// Protected routes.
		api.Group(func(protected chi.Router) {
			protected.Use(middleware.AuthMiddleware(deps.TokenMgr))

			protected.Route("/users", func(userRoutes chi.Router) {
				userHandler := NewUserHandler(
					deps.UserService,
					WithUserBodyLimit(deps.MaxBodyBytes),
					WithRefreshCookie(deps.RefreshCookie),
				)
				userRoutes.Get("/me", userHandler.GetProfile)
			})

			protected.Route("/tasks", func(taskRoutes chi.Router) {
				taskHandler := NewTaskHandler(deps.TaskService, WithTaskBodyLimit(deps.MaxBodyBytes))
				taskRoutes.Get("/", taskHandler.List)
				taskRoutes.Post("/", taskHandler.Create)
				taskRoutes.Get("/{taskID}", taskHandler.GetByID)
				taskRoutes.Put("/{taskID}", taskHandler.Update)
				taskRoutes.Delete("/{taskID}", taskHandler.Delete)
			})

			// Admin routes. The middleware reads the current role from the
			// database rather than trusting a role embedded in a token.
			protected.Group(func(adminRoutes chi.Router) {
				adminRoutes.Use(middleware.AdminMiddleware(deps.UserService))
				adminHandler := NewAdminHandler(deps.AdminService)
				adminRoutes.Route("/admin", func(adminAPI chi.Router) {
					adminAPI.Get("/users", adminHandler.ListUsers)
					adminAPI.Get("/tasks", adminHandler.ListAllTasks)
					adminAPI.Get("/users/{userID}/tasks", adminHandler.ListUserTasks)
					adminAPI.Put("/users/{userID}/promote", adminHandler.PromoteUser)
				})
			})
		})
	})

	// Serve frontend SPA (if frontend directory is set).
	if deps.FrontendDir != "" {
		fileServer := http.FileServer(http.Dir(deps.FrontendDir))

		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := deps.FrontendDir + r.URL.Path
			if _, err := os.Stat(path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, deps.FrontendDir+"/index.html")
		})

		slog.Info("frontend SPA configured", slog.String("dir", deps.FrontendDir))
	}

	slog.Info("router configured with all routes and middleware")
	return r
}
