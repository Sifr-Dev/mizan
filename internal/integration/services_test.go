package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/Sifr-dev/GO_DB/internal/delivery/handler"
	"github.com/Sifr-dev/GO_DB/internal/delivery/handler/middleware"
	"github.com/Sifr-dev/GO_DB/internal/domain"
	"github.com/Sifr-dev/GO_DB/internal/infra/auth"
	"github.com/Sifr-dev/GO_DB/internal/repository"
	"github.com/Sifr-dev/GO_DB/internal/usecase"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	integrationDatabaseURLEnv = "GO_DB_INTEGRATION_DATABASE_URL"
	integrationRedisURLEnv    = "GO_DB_INTEGRATION_REDIS_URL"
	integrationJWTSecret      = "go-db-integration-secret-with-at-least-32-bytes"
	expectedSchemaVersion     = 4
)

type serviceFixture struct {
	pool         *pgxpool.Pool
	redis        *redis.Client
	redisURL     string
	userRepo     domain.UserRepository
	userService  domain.UserService
	adminService domain.AdminService
	tokenManager *auth.TokenManager
	sessionStore auth.SessionStore
	router       http.Handler
}

func TestPostgresRegistrationLoginAndCurrentRole(t *testing.T) {
	fixture := newServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := uniqueEmail("registration")
	password := "correct horse battery staple"
	registered, err := fixture.userService.Register(ctx, domain.RegisterRequest{
		Name:     "Integration User",
		Email:    "  " + strings.ToUpper(email) + "  ",
		Password: password,
	})
	require.NoError(t, err)
	require.NotEmpty(t, registered.AccessToken)
	assert.Equal(t, email, registered.User.Email)
	assert.Equal(t, domain.RoleUser, registered.User.Role)

	stored, err := fixture.userRepo.GetByEmail(ctx, strings.ToUpper(email))
	require.NoError(t, err)
	assert.Equal(t, email, stored.Email)
	assert.NotEmpty(t, stored.PasswordHash)

	_, err = fixture.userService.Register(ctx, domain.RegisterRequest{
		Name:     "Duplicate User",
		Email:    email,
		Password: password,
	})
	assert.ErrorIs(t, err, domain.ErrEmailAlreadyInUse)

	loggedIn, err := fixture.userService.Login(ctx, domain.LoginRequest{
		Email:    strings.ToUpper(email),
		Password: password,
	})
	require.NoError(t, err)
	assert.Equal(t, email, loggedIn.User.Email)

	claims, err := fixture.tokenManager.ValidateAccessToken(ctx, loggedIn.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, stored.ID, claims.UserID)
	assert.Equal(t, domain.RoleUser, claims.Role)

	_, err = fixture.tokenManager.ValidateAccessToken(ctx, loggedIn.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)

	promoted, err := fixture.adminService.PromoteToAdmin(ctx, stored.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, promoted.Role)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	request.Header.Set("Authorization", "Bearer "+loggedIn.AccessToken)
	response := httptest.NewRecorder()
	fixture.router.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code, "authorization must use the current database role")

	stored.Role = domain.RoleUser
	require.NoError(t, fixture.userRepo.Update(ctx, stored))
	request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	request.Header.Set("Authorization", "Bearer "+loggedIn.AccessToken)
	response = httptest.NewRecorder()
	fixture.router.ServeHTTP(response, request)
	assert.Equal(t, http.StatusForbidden, response.Code)
}

func TestHTTPRefreshRotationReuseAndLogout(t *testing.T) {
	fixture := newServiceFixture(t)
	email := uniqueEmail("rotation")
	password := "correct horse battery staple"

	registerResponse := postJSON(t, fixture.router, "/api/v1/auth/register", map[string]string{
		"name":     "Rotation User",
		"email":    email,
		"password": password,
	}, "")
	require.Equal(t, http.StatusCreated, registerResponse.Code)
	registerCookie := requireCookie(t, registerResponse, "refresh_token")
	registerAuth := decodeAuthResponse(t, registerResponse)

	refreshResponse := postJSON(t, fixture.router, "/api/v1/auth/refresh", nil, registerCookie.Value)
	require.Equal(t, http.StatusOK, refreshResponse.Code)
	rotatedCookie := requireCookie(t, refreshResponse, "refresh_token")
	rotatedAuth := decodeAuthResponse(t, refreshResponse)
	assert.NotEqual(t, registerAuth.AccessToken, rotatedAuth.AccessToken)

	reuseResponse := postJSON(t, fixture.router, "/api/v1/auth/refresh", nil, registerCookie.Value)
	assert.Equal(t, http.StatusUnauthorized, reuseResponse.Code)

	_, err := fixture.tokenManager.ValidateAccessToken(context.Background(), rotatedAuth.AccessToken)
	assert.ErrorIs(t, err, auth.ErrSessionRevoked, "reuse must revoke the successor family")

	logoutResponse := postJSON(t, fixture.router, "/api/v1/auth/logout", nil, rotatedCookie.Value)
	assert.Equal(t, http.StatusNoContent, logoutResponse.Code)
}

func TestConcurrentRefreshHasOneAtomicWinner(t *testing.T) {
	fixture := newServiceFixture(t)
	email := uniqueEmail("concurrent")
	password := "correct horse battery staple"

	registerResponse := postJSON(t, fixture.router, "/api/v1/auth/register", map[string]string{
		"name":     "Concurrent User",
		"email":    email,
		"password": password,
	}, "")
	require.Equal(t, http.StatusCreated, registerResponse.Code)
	cookie := requireCookie(t, registerResponse, "refresh_token")

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			response := postJSON(t, fixture.router, "/api/v1/auth/refresh", nil, cookie.Value)
			statuses <- response.Code
		}()
	}
	close(start)
	waitGroup.Wait()
	close(statuses)

	observed := make([]int, 0, 2)
	for status := range statuses {
		observed = append(observed, status)
	}
	sort.Ints(observed)
	assert.Equal(t, []int{http.StatusOK, http.StatusUnauthorized}, observed)
}

func TestRedisSessionPersistenceAndLuaRotation(t *testing.T) {
	fixture := newServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := uuid.NewString()
	original := auth.Session{
		ID:         sessionID,
		UserID:     uuid.New(),
		Role:       domain.RoleUser,
		AccessJTI:  uuid.NewString(),
		RefreshJTI: uuid.NewString(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	require.NoError(t, fixture.sessionStore.Create(ctx, original))

	secondStore := auth.NewRedisSessionStore(fixture.redis)
	persisted, found, err := secondStore.Get(ctx, sessionID)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, original.UserID, persisted.UserID)
	assert.Equal(t, original.RefreshJTI, persisted.RefreshJTI)

	results := make(chan auth.RotationStatus, 2)
	errorsChannel := make(chan error, 2)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			next := auth.Session{
				AccessJTI:  uuid.NewString(),
				RefreshJTI: uuid.NewString(),
				Role:       domain.RoleUser,
				ExpiresAt:  original.ExpiresAt,
			}
			status, rotateErr := secondStore.Rotate(ctx, sessionID, original.RefreshJTI, next)
			results <- status
			errorsChannel <- rotateErr
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(errorsChannel)

	for rotateErr := range errorsChannel {
		require.NoError(t, rotateErr)
	}
	statuses := make([]int, 0, 2)
	for status := range results {
		statuses = append(statuses, int(status))
	}
	sort.Ints(statuses)
	assert.Equal(t, []int{int(auth.RotationSucceeded), int(auth.RotationReused)}, statuses)

	_, found, err = fixture.sessionStore.Get(ctx, sessionID)
	require.NoError(t, err)
	assert.False(t, found, "reuse detection must revoke the session family")
}

func TestRedisRateLimitExpiryAndOutagePolicy(t *testing.T) {
	fixture := newServiceFixture(t)

	limiter := middleware.NewRateLimiter(
		fixture.redis,
		1,
		150*time.Millisecond,
		middleware.WithRateLimitScope("integration-"+uuid.NewString()),
	)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
		req.RemoteAddr = "192.0.2.44:4321"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	assert.Equal(t, http.StatusNoContent, request().Code)
	assert.Equal(t, http.StatusTooManyRequests, request().Code)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, http.StatusNoContent, request().Code)

	closedClient, err := redis.ParseURL(fixture.redisURL)
	require.NoError(t, err)
	client := redis.NewClient(closedClient)
	require.NoError(t, client.Close())

	failClosed := middleware.NewRateLimiter(client, 1, time.Minute).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	response := httptest.NewRecorder()
	failClosed.ServeHTTP(response, req)
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)

	failOpen := middleware.NewRateLimiter(
		client,
		1,
		time.Minute,
		middleware.WithRateLimitFailOpen(true),
	).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	response = httptest.NewRecorder()
	failOpen.ServeHTTP(response, req)
	assert.Equal(t, http.StatusNoContent, response.Code)
}

func TestCredentialedCORSAndCookieContract(t *testing.T) {
	fixture := newServiceFixture(t)

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/refresh", nil)
	preflight.Header.Set("Origin", "https://app.example.com")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflightResponse := httptest.NewRecorder()
	fixture.router.ServeHTTP(preflightResponse, preflight)
	assert.Equal(t, "https://app.example.com", preflightResponse.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", preflightResponse.Header().Get("Access-Control-Allow-Credentials"))

	blocked := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/refresh", nil)
	blocked.Header.Set("Origin", "https://attacker.example.com")
	blocked.Header.Set("Access-Control-Request-Method", http.MethodPost)
	blockedResponse := httptest.NewRecorder()
	fixture.router.ServeHTTP(blockedResponse, blocked)
	assert.Empty(t, blockedResponse.Header().Get("Access-Control-Allow-Origin"))

	registerResponse := postJSON(t, fixture.router, "/api/v1/auth/register", map[string]string{
		"name":     "Cookie User",
		"email":    uniqueEmail("cookie"),
		"password": "correct horse battery staple",
	}, "")
	require.Equal(t, http.StatusCreated, registerResponse.Code)
	setCookie := registerResponse.Header().Get("Set-Cookie")
	assert.Contains(t, setCookie, "refresh_token=")
	assert.Contains(t, setCookie, "HttpOnly")
	assert.Contains(t, setCookie, "SameSite=Strict")
	assert.Contains(t, setCookie, "Path=/api/v1/auth")
	assert.NotContains(t, registerResponse.Body.String(), "refresh_token")
}

func newServiceFixture(t *testing.T) serviceFixture {
	t.Helper()

	databaseURL := strings.TrimSpace(os.Getenv(integrationDatabaseURLEnv))
	redisURL := strings.TrimSpace(os.Getenv(integrationRedisURLEnv))
	if databaseURL == "" || redisURL == "" {
		t.Skipf("set %s and %s to run service-backed integration tests", integrationDatabaseURLEnv, integrationRedisURLEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	require.NoError(t, pool.Ping(ctx))
	t.Cleanup(pool.Close)

	var schemaVersion int64
	var dirty bool
	err = pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&schemaVersion, &dirty)
	require.NoError(t, err, "database migrations must be applied before integration tests")
	require.False(t, dirty, "database schema must not be in a dirty migration state")
	require.Equal(t, int64(expectedSchemaVersion), schemaVersion)

	redisOptions, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	redisClient := redis.NewClient(redisOptions)
	require.NoError(t, redisClient.Ping(ctx).Err())
	t.Cleanup(func() { _ = redisClient.Close() })

	tokenManager := auth.NewTokenManager(
		integrationJWTSecret,
		5*time.Minute,
		time.Hour,
		auth.NewRedisSessionStore(redisClient),
	)
	userRepo := repository.NewUserRepo(pool)
	taskRepo := repository.NewTaskRepo(pool)
	userService := usecase.NewUserService(userRepo, tokenManager)
	taskService := usecase.NewTaskService(taskRepo, userRepo)
	adminService := usecase.NewAdminService(userRepo, taskRepo)

	router := handler.NewRouter(&handler.Dependencies{
		UserService:       userService,
		TaskService:       taskService,
		AdminService:      adminService,
		TokenMgr:          tokenManager,
		RedisClient:       redisClient,
		AllowedOrigins:    []string{"https://app.example.com"},
		RateLimitMax:      1000,
		RateLimitWindow:   time.Minute,
		RateLimitFailOpen: false,
		RateLimitScope:    "integration-" + uuid.NewString(),
		MaxBodyBytes:      64 << 10,
		RefreshCookie: handler.CookieConfig{
			Name:           "refresh_token",
			Path:           "/api/v1/auth",
			SameSite:       http.SameSiteStrictMode,
			MaxAge:         int(time.Hour.Seconds()),
			AllowedOrigins: []string{"https://app.example.com"},
		},
	})

	return serviceFixture{
		pool:         pool,
		redis:        redisClient,
		redisURL:     redisURL,
		userRepo:     userRepo,
		userService:  userService,
		adminService: adminService,
		tokenManager: tokenManager,
		sessionStore: auth.NewRedisSessionStore(redisClient),
		router:       router,
	}
}

func postJSON(t *testing.T, router http.Handler, path string, payload any, cookieValue string) *httptest.ResponseRecorder {
	t.Helper()

	var body bytes.Buffer
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Errorf("encode request payload: %v", err)
		} else {
			_, _ = body.Write(encoded)
		}
	}
	request := httptest.NewRequest(http.MethodPost, path, &body)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookieValue != "" {
		request.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookieValue})
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func requireCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q", name)
	return nil
}

func decodeAuthResponse(t *testing.T, response *httptest.ResponseRecorder) domain.AuthResponse {
	t.Helper()

	var envelope struct {
		Success bool                `json:"success"`
		Data    domain.AuthResponse `json:"data"`
		Error   string              `json:"error"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	require.True(t, envelope.Success, envelope.Error)
	return envelope.Data
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%s@example.com", prefix, uuid.NewString())
}
