package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/Sifr-Dev/GO_DB/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testUserService struct {
	register func(context.Context, domain.RegisterRequest) (*domain.AuthResponse, error)
	login    func(context.Context, domain.LoginRequest) (*domain.AuthResponse, error)
	refresh  func(context.Context, string) (*domain.AuthResponse, error)
	logout   func(context.Context, string) error
	profile  func(context.Context, uuid.UUID) (*domain.User, error)
}

func (s *testUserService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.AuthResponse, error) {
	if s.register == nil {
		return nil, errors.New("not configured")
	}
	return s.register(ctx, req)
}

func (s *testUserService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	if s.login == nil {
		return nil, errors.New("not configured")
	}
	return s.login(ctx, req)
}

func (s *testUserService) Refresh(ctx context.Context, token string) (*domain.AuthResponse, error) {
	if s.refresh == nil {
		return nil, errors.New("not configured")
	}
	return s.refresh(ctx, token)
}

func (s *testUserService) Logout(ctx context.Context, token string) error {
	if s.logout == nil {
		return nil
	}
	return s.logout(ctx, token)
}

func (s *testUserService) GetProfile(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if s.profile == nil {
		return nil, domain.ErrNotFound
	}
	return s.profile(ctx, id)
}

func TestDecodeJSONEnforcesMediaTypeSizeAndFraming(t *testing.T) {
	var target struct {
		Name string `json:"name"`
	}

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}`))
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	err := decodeJSON(recorder, request, &target, 1024)
	assert.ErrorIs(t, err, ErrUnsupportedMediaType)

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}`))
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = 2000
	recorder = httptest.NewRecorder()
	err = decodeJSON(recorder, request, &target, 1024)
	assert.ErrorIs(t, err, ErrBodyTooLarge)

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"} {"name":"extra"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	err = decodeJSON(recorder, request, &target, 1024)
	assert.ErrorIs(t, err, ErrTrailingJSON)

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok","unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	err = decodeJSON(recorder, request, &target, 1024)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrTrailingJSON)
}

func TestUserHandlerDoesNotExposeRefreshTokenAndSetsHttpOnlyCookie(t *testing.T) {
	service := &testUserService{
		register: func(_ context.Context, req domain.RegisterRequest) (*domain.AuthResponse, error) {
			return &domain.AuthResponse{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				User:         domain.User{ID: uuid.New(), Name: req.Name, Email: req.Email, Role: domain.RoleUser},
			}, nil
		},
	}
	handler := NewUserHandler(service, WithUserBodyLimit(1024), WithRefreshCookie(CookieConfig{
		Name:     "refresh_token",
		Path:     "/api/v1/auth",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	}))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"name":"Owner","email":"owner@example.com","password":"securepassword"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.Register(recorder, request)

	require.Equal(t, http.StatusCreated, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), "refresh-token")
	assert.Contains(t, recorder.Header().Get("Set-Cookie"), "refresh_token=")
	assert.Contains(t, recorder.Header().Get("Set-Cookie"), "HttpOnly")
	assert.Contains(t, recorder.Header().Get("Set-Cookie"), "SameSite=Strict")
}

func TestUserHandlerMapsRegistrationConflictTo409(t *testing.T) {
	service := &testUserService{
		register: func(context.Context, domain.RegisterRequest) (*domain.AuthResponse, error) {
			return nil, domain.ErrEmailAlreadyInUse
		},
	}
	handler := NewUserHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"name":"Owner","email":"owner@example.com","password":"securepassword"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.Register(recorder, request)

	assert.Equal(t, http.StatusConflict, recorder.Code)
	var response APIResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.False(t, response.Success)
	assert.Equal(t, "email already in use", response.Error)
}

func TestUserHandlerMapsSessionStoreOutageTo503(t *testing.T) {
	service := &testUserService{
		refresh: func(context.Context, string) (*domain.AuthResponse, error) {
			return nil, domain.ErrUnavailable
		},
	}
	handler := NewUserHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	recorder := httptest.NewRecorder()
	handler.Refresh(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

func TestCookieAuthEndpointsEnforceOriginPolicy(t *testing.T) {
	service := &testUserService{
		refresh: func(context.Context, string) (*domain.AuthResponse, error) {
			return &domain.AuthResponse{AccessToken: "access-token", RefreshToken: "refresh-token"}, nil
		},
	}
	handler := NewUserHandler(service, WithRefreshCookie(CookieConfig{
		Name:           "refresh_token",
		Path:           "/api/v1/auth",
		SameSite:       http.SameSiteStrictMode,
		AllowedOrigins: []string{"https://app.example.com"},
	}))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	recorder := httptest.NewRecorder()
	handler.Refresh(recorder, request)
	assert.Equal(t, http.StatusForbidden, recorder.Code)

	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	recorder = httptest.NewRecorder()
	handler.Refresh(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestSameSiteNoneRequiresBrowserOrigin(t *testing.T) {
	handler := NewUserHandler(&testUserService{}, WithRefreshCookie(CookieConfig{
		Name:     "refresh_token",
		Path:     "/api/v1/auth",
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	recorder := httptest.NewRecorder()
	handler.Refresh(recorder, request)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestRouterUsesExplicitCredentialedCORSAllowlist(t *testing.T) {
	router := NewRouter(&Dependencies{AllowedOrigins: []string{"https://app.example.com"}})

	request := httptest.NewRequest(http.MethodOptions, "/health", nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	assert.Equal(t, "https://app.example.com", recorder.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", recorder.Header().Get("Access-Control-Allow-Credentials"))

	request = httptest.NewRequest(http.MethodOptions, "/health", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Empty(t, recorder.Header().Get("Access-Control-Allow-Origin"))
}

func TestRouterWithEmptyCORSAllowlistDoesNotGrantCrossOriginAccess(t *testing.T) {
	router := NewRouter(&Dependencies{})

	request := httptest.NewRequest(http.MethodOptions, "/health", nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	assert.Empty(t, recorder.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, recorder.Header().Get("Access-Control-Allow-Credentials"))
}
