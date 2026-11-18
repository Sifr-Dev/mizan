package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/Sifr-dev/GO_DB/internal/domain"
)

type CookieConfig struct {
	Name           string
	Path           string
	Secure         bool
	SameSite       http.SameSite
	MaxAge         int
	AllowedOrigins []string
}

type UserHandler struct {
	userService   domain.UserService
	validate      *validator.Validate
	maxBodyBytes  int64
	refreshCookie CookieConfig
}

type UserHandlerOption func(*UserHandler)

func WithUserBodyLimit(maxBodyBytes int64) UserHandlerOption {
	return func(handler *UserHandler) {
		if maxBodyBytes > 0 {
			handler.maxBodyBytes = maxBodyBytes
		}
	}
}

func WithRefreshCookie(config CookieConfig) UserHandlerOption {
	return func(handler *UserHandler) {
		handler.refreshCookie = config
	}
}

func NewUserHandler(userService domain.UserService, options ...UserHandlerOption) *UserHandler {
	handler := &UserHandler{
		userService:  userService,
		validate:     validator.New(),
		maxBodyBytes: defaultMaxBodyBytes,
		refreshCookie: CookieConfig{
			Name:     "refresh_token",
			Path:     "/api/v1/auth",
			SameSite: http.SameSiteStrictMode,
		},
	}
	for _, option := range options {
		option(handler)
	}
	return handler
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := decodeJSON(w, r, &req, h.maxBodyBytes); err != nil {
		respondDecodeError(w, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = domain.NormalizeEmail(req.Email)

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := h.userService.Register(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrEmailAlreadyInUse):
			respondError(w, http.StatusConflict, "email already in use")
		case errors.Is(err, domain.ErrInvalidInput):
			respondError(w, http.StatusBadRequest, "invalid request")
		case errors.Is(err, domain.ErrUnavailable):
			respondError(w, http.StatusServiceUnavailable, "authentication service unavailable")
		default:
			respondError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	h.setRefreshCookie(w, resp.RefreshToken, resp.RefreshExpiresAt)
	respondJSON(w, http.StatusCreated, resp)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := decodeJSON(w, r, &req, h.maxBodyBytes); err != nil {
		respondDecodeError(w, err)
		return
	}
	req.Email = domain.NormalizeEmail(req.Email)

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := h.userService.Login(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCreds):
			respondError(w, http.StatusUnauthorized, "invalid email or password")
		case errors.Is(err, domain.ErrUnavailable):
			respondError(w, http.StatusServiceUnavailable, "authentication service unavailable")
		default:
			respondError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	h.setRefreshCookie(w, resp.RefreshToken, resp.RefreshExpiresAt)
	respondJSON(w, http.StatusOK, resp)
}

func (h *UserHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if !h.cookieRequestOriginAllowed(r) {
		respondError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}

	cookie, err := r.Cookie(h.cookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		respondError(w, http.StatusUnauthorized, "refresh session not found")
		return
	}

	resp, err := h.userService.Refresh(r.Context(), cookie.Value)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCreds):
			h.clearRefreshCookie(w)
			respondError(w, http.StatusUnauthorized, "invalid or expired refresh session")
		case errors.Is(err, domain.ErrUnavailable):
			respondError(w, http.StatusServiceUnavailable, "authentication service unavailable")
		default:
			respondError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	h.setRefreshCookie(w, resp.RefreshToken, resp.RefreshExpiresAt)
	respondJSON(w, http.StatusOK, resp)
}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if !h.cookieRequestOriginAllowed(r) {
		respondError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}

	cookie, err := r.Cookie(h.cookieName())
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		if err := h.userService.Logout(r.Context(), cookie.Value); err != nil {
			if errors.Is(err, domain.ErrUnavailable) {
				respondError(w, http.StatusServiceUnavailable, "authentication service unavailable")
				return
			}
			respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userService.GetProfile(r.Context(), *userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			respondError(w, http.StatusNotFound, "user not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	respondJSON(w, http.StatusOK, user)
}

func (h *UserHandler) cookieName() string {
	if h.refreshCookie.Name == "" {
		return "refresh_token"
	}
	return h.refreshCookie.Name
}

func (h *UserHandler) setRefreshCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	if value == "" {
		return
	}
	maxAge := h.refreshCookie.MaxAge
	if maxAge <= 0 {
		maxAge = int((7 * 24 * time.Hour).Seconds())
	}
	if !expiresAt.IsZero() {
		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			return
		}
		maxAge = int(remaining.Seconds())
		if maxAge < 1 {
			maxAge = 1
		}
	}
	cookie := &http.Cookie{
		Name:     h.cookieName(),
		Value:    value,
		Path:     h.refreshCookie.Path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.refreshCookie.Secure,
		SameSite: h.refreshCookie.SameSite,
	}
	if !expiresAt.IsZero() {
		cookie.Expires = expiresAt.UTC()
	}
	http.SetCookie(w, cookie)
}

func (h *UserHandler) clearRefreshCookie(w http.ResponseWriter) {
	path := h.refreshCookie.Path
	if path == "" {
		path = "/api/v1/auth"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName(),
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.refreshCookie.Secure,
		SameSite: h.refreshCookie.SameSite,
	})
}
