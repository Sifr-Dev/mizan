package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/mohamedsalahi/GO_DB/internal/domain"
	"github.com/mohamedsalahi/GO_DB/internal/infra/auth"
)

type contextKey string

const UserIDKey contextKey = "user_id"

func AuthMiddleware(tokenManager *auth.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			parts := strings.Fields(authHeader)
			if len(parts) == 0 {
				writeMiddlewareError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
				writeMiddlewareError(w, http.StatusUnauthorized, "invalid authorization header format")
				return
			}

			claims, err := tokenManager.ValidateAccessToken(r.Context(), parts[1])
			if err != nil {
				if errors.Is(err, auth.ErrSessionUnavailable) {
					writeMiddlewareError(w, http.StatusServiceUnavailable, "authentication service unavailable")
					return
				}
				writeMiddlewareError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUserID(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(UserIDKey).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// AdminMiddleware checks the current database role instead of trusting a role
// copied into a bearer token. The resolver is required: production
// authorization must always resolve the account's current role from the
// database.
func AdminMiddleware(resolver domain.UserService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserID(r.Context())
			if userID == uuid.Nil {
				writeMiddlewareError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if resolver == nil {
				writeMiddlewareError(w, http.StatusServiceUnavailable, "authorization service unavailable")
				return
			}

			user, err := resolver.GetProfile(r.Context(), userID)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					writeMiddlewareError(w, http.StatusUnauthorized, "unauthorized")
					return
				}
				writeMiddlewareError(w, http.StatusServiceUnavailable, "authorization service unavailable")
				return
			}
			if user == nil {
				writeMiddlewareError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			if user.Role != domain.RoleAdmin {
				writeMiddlewareError(w, http.StatusForbidden, "forbidden: admin access required")
				return
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}
}

func writeMiddlewareError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
