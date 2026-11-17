package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	DefaultIssuer   = "go-clean-api"
	DefaultAudience = "go-clean-api-client"
)

var (
	// ErrInvalidToken indicates that a token is malformed, expired, has the
	// wrong signature, or does not satisfy the requested token purpose.
	ErrInvalidToken = errors.New("invalid token")
	// ErrSessionRevoked indicates that a valid-looking token refers to a
	// session that has been consumed or revoked.
	ErrSessionRevoked = errors.New("session revoked")
	// ErrRefreshTokenReused indicates that a consumed refresh token was
	// presented again. The successor session is revoked as a precaution.
	ErrRefreshTokenReused = errors.New("refresh token reused")
	// ErrSessionUnavailable indicates that the session backing a token could
	// not be checked. Callers should fail closed for protected routes.
	ErrSessionUnavailable = errors.New("session store unavailable")
	// ErrSessionStoreRequired indicates that a token manager was constructed
	// without an explicit session-store implementation.
	ErrSessionStoreRequired = errors.New("session store is required")
)

type TokenUse string

const (
	TokenUseAccess  TokenUse = "access"
	TokenUseRefresh TokenUse = "refresh"
)

// Claims is the deliberately small claim set issued by this service.
type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	TokenUse  TokenUse  `json:"token_use"`
	SessionID string    `json:"sid"`
	jwt.RegisteredClaims
}

// TokenPair contains the two short-lived browser credentials. The refresh
// token is returned to the HTTP layer, which places it in an HttpOnly cookie.
type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type TokenManager struct {
	secret            []byte
	issuer            string
	audience          string
	accessExpiration  time.Duration
	refreshExpiration time.Duration
	sessions          SessionStore
	now               func() time.Time
}

type TokenManagerOption func(*TokenManager)

func WithIssuer(issuer string) TokenManagerOption {
	return func(manager *TokenManager) {
		manager.issuer = issuer
	}
}

func WithAudience(audience string) TokenManagerOption {
	return func(manager *TokenManager) {
		manager.audience = audience
	}
}

func WithClock(now func() time.Time) TokenManagerOption {
	return func(manager *TokenManager) {
		if now != nil {
			manager.now = now
		}
	}
}

// NewTokenManager requires an explicit session store. Production code should
// use RedisSessionStore; MemorySessionStore is intended for focused tests.
func NewTokenManager(
	secret string,
	accessExp time.Duration,
	refreshExp time.Duration,
	sessions SessionStore,
	options ...TokenManagerOption,
) *TokenManager {
	manager := &TokenManager{
		secret:            []byte(secret),
		issuer:            DefaultIssuer,
		audience:          DefaultAudience,
		accessExpiration:  accessExp,
		refreshExpiration: refreshExp,
		sessions:          sessions,
		now:               time.Now,
	}
	for _, option := range options {
		option(manager)
	}
	return manager
}

// IssueTokens creates one server-side session family and returns an
// access/refresh pair bound to it. Both tokens carry the same session ID, but
// have distinct token_use values and cannot be used interchangeably.
func (m *TokenManager) IssueTokens(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	if m.sessions == nil {
		return nil, ErrSessionStoreRequired
	}
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user id is required", ErrInvalidToken)
	}
	if m.accessExpiration <= 0 || m.refreshExpiration <= 0 {
		return nil, fmt.Errorf("%w: token expiration durations must be positive", ErrInvalidToken)
	}

	now := m.now().UTC()
	session := Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		Role:      role,
		ExpiresAt: now.Add(m.refreshExpiration),
	}
	generated, err := m.generatePair(session, now)
	if err != nil {
		return nil, err
	}
	session.AccessJTI = generated.accessJTI
	session.RefreshJTI = generated.refreshJTI

	if err := m.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	return generated.pair, nil
}

// RefreshTokens atomically consumes the current refresh token and issues a new
// access/refresh pair in the same session family. The family expiry is
// absolute and is not extended by rotation. Reuse of an already-consumed
// refresh token revokes the successor credentials.
func (m *TokenManager) RefreshTokens(ctx context.Context, refreshToken, role string) (*TokenPair, error) {
	if m.sessions == nil {
		return nil, ErrSessionStoreRequired
	}
	claims, err := m.parseClaims(refreshToken, TokenUseRefresh)
	if err != nil {
		return nil, err
	}

	session, ok, err := m.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	if !ok || session.UserID != claims.UserID {
		return nil, ErrSessionRevoked
	}
	if containsString(session.ConsumedRefreshJTIs, claims.ID) {
		if revokeErr := m.sessions.Revoke(ctx, claims.SessionID); revokeErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, revokeErr)
		}
		return nil, ErrRefreshTokenReused
	}
	if session.RefreshJTI != claims.ID {
		return nil, ErrSessionRevoked
	}

	now := m.now().UTC()
	next := Session{
		ID:        session.ID,
		UserID:    session.UserID,
		Role:      role,
		ExpiresAt: session.ExpiresAt,
	}
	generated, err := m.generatePair(next, now)
	if err != nil {
		return nil, err
	}
	next.AccessJTI = generated.accessJTI
	next.RefreshJTI = generated.refreshJTI

	status, err := m.sessions.Rotate(ctx, claims.SessionID, claims.ID, next)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	switch status {
	case RotationSucceeded:
		return generated.pair, nil
	case RotationReused:
		return nil, ErrRefreshTokenReused
	default:
		return nil, ErrSessionRevoked
	}
}

// RevokeRefreshToken consumes the session family associated with a refresh
// token. Revocation is idempotent for an already-consumed session.
func (m *TokenManager) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if m.sessions == nil {
		return ErrSessionStoreRequired
	}
	claims, err := m.parseClaims(refreshToken, TokenUseRefresh)
	if err != nil {
		return err
	}
	if err := m.sessions.Revoke(ctx, claims.SessionID); err != nil {
		return fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	return nil
}

// ValidateAccessToken validates an access token and confirms that its JTI is
// the current access credential for an active session. Refresh tokens are
// rejected even if their signature is otherwise valid.
func (m *TokenManager) ValidateAccessToken(ctx context.Context, token string) (*Claims, error) {
	if m.sessions == nil {
		return nil, ErrSessionStoreRequired
	}
	claims, err := m.parseClaims(token, TokenUseAccess)
	if err != nil {
		return nil, err
	}

	session, ok, err := m.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	if !ok || session.UserID != claims.UserID || session.AccessJTI != claims.ID {
		return nil, ErrSessionRevoked
	}
	return claims, nil
}

// ValidateRefreshToken validates a refresh token and confirms that its JTI is
// the current refresh credential for an active session. Presenting a consumed
// token revokes the whole family.
func (m *TokenManager) ValidateRefreshToken(ctx context.Context, token string) (*Claims, error) {
	if m.sessions == nil {
		return nil, ErrSessionStoreRequired
	}
	claims, err := m.parseClaims(token, TokenUseRefresh)
	if err != nil {
		return nil, err
	}

	session, ok, err := m.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	if !ok || session.UserID != claims.UserID {
		return nil, ErrSessionRevoked
	}
	if containsString(session.ConsumedRefreshJTIs, claims.ID) {
		if revokeErr := m.sessions.Revoke(ctx, claims.SessionID); revokeErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrSessionUnavailable, revokeErr)
		}
		return nil, ErrRefreshTokenReused
	}
	if session.RefreshJTI != claims.ID {
		return nil, ErrSessionRevoked
	}
	return claims, nil
}

type generatedTokens struct {
	pair       *TokenPair
	accessJTI  string
	refreshJTI string
}

func (m *TokenManager) generatePair(session Session, now time.Time) (generatedTokens, error) {
	accessJTI := uuid.NewString()
	refreshJTI := uuid.NewString()

	accessExpiresAt := now.Add(m.accessExpiration)
	if accessExpiresAt.After(session.ExpiresAt) {
		accessExpiresAt = session.ExpiresAt
	}
	accessToken, err := m.generateToken(session, TokenUseAccess, accessJTI, now, accessExpiresAt)
	if err != nil {
		return generatedTokens{}, fmt.Errorf("generate access token: %w", err)
	}
	refreshToken, err := m.generateToken(session, TokenUseRefresh, refreshJTI, now, session.ExpiresAt)
	if err != nil {
		return generatedTokens{}, fmt.Errorf("generate refresh token: %w", err)
	}

	return generatedTokens{
		pair: &TokenPair{
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			RefreshExpiresAt: session.ExpiresAt,
		},
		accessJTI:  accessJTI,
		refreshJTI: refreshJTI,
	}, nil
}

func (m *TokenManager) generateToken(session Session, use TokenUse, jti string, now, expiresAt time.Time) (string, error) {
	claims := &Claims{
		UserID:    session.UserID,
		Role:      session.Role,
		TokenUse:  use,
		SessionID: session.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   session.UserID.String(),
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *TokenManager) parseClaims(raw string, expectedUse TokenUse) (*Claims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidToken
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.TokenUse != expectedUse {
		return nil, fmt.Errorf("%w: token purpose %q cannot be used as %q", ErrInvalidToken, claims.TokenUse, expectedUse)
	}
	if claims.UserID == uuid.Nil || claims.SessionID == "" || claims.ID == "" {
		return nil, fmt.Errorf("%w: required claims are missing", ErrInvalidToken)
	}
	if claims.Subject != claims.UserID.String() {
		return nil, fmt.Errorf("%w: subject does not match user id", ErrInvalidToken)
	}
	return claims, nil
}
