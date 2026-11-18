package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/Sifr-Dev/GO_DB/internal/domain"
	"github.com/Sifr-Dev/GO_DB/internal/infra/auth"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type middlewareUserService struct {
	role       string
	profileErr error
}

func (s middlewareUserService) Register(context.Context, domain.RegisterRequest) (*domain.AuthResponse, error) {
	return nil, nil
}
func (s middlewareUserService) Login(context.Context, domain.LoginRequest) (*domain.AuthResponse, error) {
	return nil, nil
}
func (s middlewareUserService) Refresh(context.Context, string) (*domain.AuthResponse, error) {
	return nil, nil
}
func (s middlewareUserService) Logout(context.Context, string) error { return nil }
func (s middlewareUserService) GetProfile(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if s.profileErr != nil {
		return nil, s.profileErr
	}
	return &domain.User{ID: id, Role: s.role}, nil
}

func TestAuthMiddlewareRejectsRefreshTokensAndRevokedAccessTokens(t *testing.T) {
	manager := auth.NewTokenManager("a sufficiently long test secret for JWTs", 15*time.Minute, time.Hour, auth.NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), domain.RoleUser)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := AuthMiddleware(manager)(next)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+pair.RefreshToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	request = httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNoContent, recorder.Code)

	require.NoError(t, manager.RevokeRefreshToken(context.Background(), pair.RefreshToken))
	request = httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAdminMiddlewareUsesCurrentDatabaseRole(t *testing.T) {
	manager := auth.NewTokenManager("a sufficiently long test secret for JWTs", 15*time.Minute, time.Hour, auth.NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), domain.RoleAdmin)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := AuthMiddleware(manager)(AdminMiddleware(middlewareUserService{role: domain.RoleUser})(next))
	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusForbidden, recorder.Code)

	handler = AuthMiddleware(manager)(AdminMiddleware(middlewareUserService{role: domain.RoleAdmin})(next))
	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestAdminMiddlewareFailsClosedWithoutDatabaseResolver(t *testing.T) {
	manager := auth.NewTokenManager("a sufficiently long test secret for JWTs", 15*time.Minute, time.Hour, auth.NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), domain.RoleAdmin)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := AuthMiddleware(manager)(AdminMiddleware(nil)(next))
	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

func TestAdminMiddlewareFailsClosedWhenRoleLookupFails(t *testing.T) {
	manager := auth.NewTokenManager("a sufficiently long test secret for JWTs", 15*time.Minute, time.Hour, auth.NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), domain.RoleAdmin)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := AuthMiddleware(manager)(AdminMiddleware(middlewareUserService{
		role:       domain.RoleAdmin,
		profileErr: errors.New("database unavailable"),
	})(next))
	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

type fakeEvaler struct {
	result []interface{}
	err    error
	calls  int
	keys   [][]string
}

func (f *fakeEvaler) Eval(_ context.Context, _ string, keys []string, _ ...interface{}) *redis.Cmd {
	f.calls++
	f.keys = append(f.keys, append([]string(nil), keys...))
	if f.err != nil {
		return redis.NewCmdResult(nil, f.err)
	}
	return redis.NewCmdResult(f.result, nil)
}

func TestRateLimiterUsesAtomicResultAndRejectsOverLimit(t *testing.T) {
	client := &fakeEvaler{result: []interface{}{int64(2), int64(5000)}}
	limiter := NewRateLimiter(nil, 1, time.Minute, WithRateLimitClient(client))
	nextCalled := false
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	request.RemoteAddr = "192.0.2.10:4321"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusTooManyRequests, recorder.Code)
	assert.False(t, nextCalled)
	assert.Equal(t, "1", recorder.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", recorder.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, recorder.Header().Get("X-RateLimit-Reset"))
	assert.NotEmpty(t, recorder.Header().Get("Retry-After"))
}

func TestRateLimiterOutagePolicyIsExplicit(t *testing.T) {
	client := &fakeEvaler{err: errors.New("redis unavailable")}
	limiter := NewRateLimiter(nil, 1, time.Minute, WithRateLimitClient(client))
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)

	limiter = NewRateLimiter(nil, 1, time.Minute, WithRateLimitClient(client), WithRateLimitFailOpen(true))
	handler = limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestRateLimiterSeparatesAuthScopeAndSkipsPreflight(t *testing.T) {
	client := &fakeEvaler{result: []interface{}{int64(1), int64(5000)}}
	limiter := NewRateLimiter(nil, 10, time.Minute, WithRateLimitClient(client))
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, preflight)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
	assert.Equal(t, 0, client.calls)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Len(t, client.keys, 1)
	assert.Contains(t, client.keys[0][0], ":auth:")
}

func TestClientIPMiddlewareOnlyTrustsConfiguredProxy(t *testing.T) {
	_, network, err := net.ParseCIDR("192.0.2.0/24")
	require.NoError(t, err)
	handler := ClientIPMiddleware([]*net.IPNet{network})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(ClientIP(r)))
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, "198.51.100.10", recorder.Body.String())

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 192.0.2.11")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, "203.0.113.9", recorder.Body.String())

	// The right-most untrusted address wins, so a spoofed left-most value
	// cannot override the client address appended by a trusted proxy.
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.9")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, "203.0.113.9", recorder.Body.String())

	// A malformed trusted chain fails closed to the immediate peer.
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, not-an-ip")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, "192.0.2.10", recorder.Body.String())

	// X-Real-IP is never used as an unconfigured fallback.
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("X-Real-IP", "203.0.113.9")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, "198.51.100.10", recorder.Body.String())

	_, ipv6Network, err := net.ParseCIDR("2001:db8::/32")
	require.NoError(t, err)
	ipv6Handler := ClientIPMiddleware([]*net.IPNet{ipv6Network})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(ClientIP(r)))
	}))
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "[2001:db8::10]:1234"
	request.Header.Set("X-Forwarded-For", "2001:db9::20")
	recorder = httptest.NewRecorder()
	ipv6Handler.ServeHTTP(recorder, request)
	assert.Equal(t, "2001:db9::20", recorder.Body.String())
}
