package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testJWTSecret = "a sufficiently long test secret for JWTs"

func TestTokenManagerSeparatesAccessAndRefreshTokens(t *testing.T) {
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	userID := uuid.New()

	pair, err := manager.IssueTokens(context.Background(), userID, "user")
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	accessClaims, err := manager.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, TokenUseAccess, accessClaims.TokenUse)
	assert.Equal(t, userID, accessClaims.UserID)
	assert.NotEmpty(t, accessClaims.ID)
	assert.NotEmpty(t, accessClaims.SessionID)
	assert.Equal(t, DefaultIssuer, accessClaims.Issuer)
	assert.Equal(t, jwt.ClaimStrings{DefaultAudience}, accessClaims.Audience)

	refreshClaims, err := manager.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, TokenUseRefresh, refreshClaims.TokenUse)
	assert.Equal(t, accessClaims.SessionID, refreshClaims.SessionID)

	_, err = manager.ValidateAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
	_, err = manager.ValidateRefreshToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestTokenManagerRejectsNonHS256Tokens(t *testing.T) {
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), "user")
	require.NoError(t, err)

	claims, err := manager.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	claimsCopy := *claims
	claimsCopy.RegisteredClaims.ID = uuid.NewString()
	hs512 := jwt.NewWithClaims(jwt.SigningMethodHS512, &claimsCopy)
	signed, err := hs512.SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = manager.ValidateAccessToken(context.Background(), signed)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestTokenManagerBindsAccessJTItoSession(t *testing.T) {
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), "user")
	require.NoError(t, err)

	claims, err := manager.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	claimsCopy := *claims
	claimsCopy.RegisteredClaims.ID = uuid.NewString()
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, &claimsCopy)
	signed, err := forged.SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = manager.ValidateAccessToken(context.Background(), signed)
	assert.ErrorIs(t, err, ErrSessionRevoked)
}

func TestTokenManagerRotatesAndRevokesSessions(t *testing.T) {
	ctx := context.Background()
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	pair, err := manager.IssueTokens(ctx, uuid.New(), "user")
	require.NoError(t, err)

	rotated, err := manager.RefreshTokens(ctx, pair.RefreshToken, "admin")
	require.NoError(t, err)
	assert.NotEqual(t, pair.AccessToken, rotated.AccessToken)
	assert.NotEqual(t, pair.RefreshToken, rotated.RefreshToken)
	assert.Equal(t, pair.RefreshExpiresAt, rotated.RefreshExpiresAt)

	rotatedClaims, err := manager.ValidateRefreshToken(ctx, rotated.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "admin", rotatedClaims.Role)

	_, err = manager.ValidateAccessToken(ctx, pair.AccessToken)
	assert.ErrorIs(t, err, ErrSessionRevoked)

	require.NoError(t, manager.RevokeRefreshToken(ctx, rotated.RefreshToken))
	_, err = manager.ValidateAccessToken(ctx, rotated.AccessToken)
	assert.ErrorIs(t, err, ErrSessionRevoked)
}

func TestTokenManagerRevokesSuccessorWhenRefreshTokenIsReused(t *testing.T) {
	ctx := context.Background()
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	pair, err := manager.IssueTokens(ctx, uuid.New(), "user")
	require.NoError(t, err)

	rotated, err := manager.RefreshTokens(ctx, pair.RefreshToken, "user")
	require.NoError(t, err)

	_, err = manager.RefreshTokens(ctx, pair.RefreshToken, "user")
	assert.ErrorIs(t, err, ErrRefreshTokenReused)

	_, err = manager.ValidateAccessToken(ctx, rotated.AccessToken)
	assert.ErrorIs(t, err, ErrSessionRevoked)
	_, err = manager.ValidateRefreshToken(ctx, rotated.RefreshToken)
	assert.ErrorIs(t, err, ErrSessionRevoked)
}

func TestTokenManagerConcurrentRefreshConsumesTokenOnce(t *testing.T) {
	ctx := context.Background()
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, NewMemorySessionStore())
	pair, err := manager.IssueTokens(ctx, uuid.New(), "user")
	require.NoError(t, err)

	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, refreshErr := manager.RefreshTokens(ctx, pair.RefreshToken, "user")
			results <- refreshErr
		}()
	}
	wait.Wait()
	close(results)

	successes := 0
	reuses := 0
	for refreshErr := range results {
		switch {
		case refreshErr == nil:
			successes++
		case errors.Is(refreshErr, ErrRefreshTokenReused):
			reuses++
		default:
			t.Fatalf("unexpected refresh result: %v", refreshErr)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, reuses)
}

func TestTokenManagerHonorsIssuerAndAudience(t *testing.T) {
	manager := NewTokenManager(
		testJWTSecret,
		15*time.Minute,
		time.Hour,
		NewMemorySessionStore(),
		WithIssuer("issuer-a"),
		WithAudience("audience-a"),
	)
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), "user")
	require.NoError(t, err)

	other := NewTokenManager(
		testJWTSecret,
		15*time.Minute,
		time.Hour,
		NewMemorySessionStore(),
		WithIssuer("issuer-b"),
		WithAudience("audience-b"),
	)
	_, err = other.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestTokenManagerFailsClosedWhenSessionStoreIsUnavailable(t *testing.T) {
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, errorSessionStore{})
	pair, err := manager.IssueTokens(context.Background(), uuid.New(), "user")
	require.NoError(t, err)

	_, err = manager.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.True(t, errors.Is(err, ErrSessionUnavailable))
}

func TestTokenManagerRequiresExplicitSessionStore(t *testing.T) {
	manager := NewTokenManager(testJWTSecret, 15*time.Minute, time.Hour, nil)
	_, err := manager.IssueTokens(context.Background(), uuid.New(), "user")
	assert.ErrorIs(t, err, ErrSessionStoreRequired)
}

type errorSessionStore struct{}

func (errorSessionStore) Create(context.Context, Session) error { return nil }
func (errorSessionStore) Get(context.Context, string) (Session, bool, error) {
	return Session{}, false, errors.New("unavailable")
}
func (errorSessionStore) Revoke(context.Context, string) error { return errors.New("unavailable") }
func (errorSessionStore) Rotate(context.Context, string, string, Session) (RotationStatus, error) {
	return RotationRejected, errors.New("unavailable")
}
