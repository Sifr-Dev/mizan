package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/mohamedsalahi/GO_DB/internal/infra/auth"
)

type contextKey string

const UserIDKey contextKey = "user_id"
const UserRoleKey contextKey = "user_role"

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
			ctx = context.WithValue(ctx, UserRoleKey, claims.Role)
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

func GetUserRole(ctx context.Context) string {
	if role, ok := ctx.Value(UserRoleKey).(string); ok {
		return role
	}
	return ""
}

// AdminMiddleware retains the legacy route signature during the token
// lifecycle migration. The authorization-boundary commit replaces it with a
// required current-role database resolver.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetUserRole(r.Context()) != "admin" {
			writeMiddlewareError(w, http.StatusForbidden, "forbidden: admin access required")
			return
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func writeMiddlewareError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
