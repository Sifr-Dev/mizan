package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/Sifr-dev/GO_DB/internal/domain"
	"github.com/Sifr-dev/GO_DB/internal/infra/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func setupUserService() (*MockUserRepo, *auth.TokenManager, domain.UserService) {
	mockRepo := new(MockUserRepo)
	tokenMgr := auth.NewTokenManager("test-secret-key", 15*time.Minute, 7*24*time.Hour, auth.NewMemorySessionStore())
	svc := NewUserService(mockRepo, tokenMgr)
	return mockRepo, tokenMgr, svc
}

func TestUserService_Register_Success(t *testing.T) {
	mockRepo, _, svc := setupUserService()

	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(nil, domain.ErrNotFound)
	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
		return u.Name == "John Doe" && u.Email == "john@example.com"
	})).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(1).(*domain.User)
		u.ID = uuid.New()
		u.CreatedAt = time.Now()
		u.UpdatedAt = time.Now()
	})

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "securepassword",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "John Doe", resp.User.Name)
	assert.Equal(t, "john@example.com", resp.User.Email)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_EmailAlreadyExists(t *testing.T) {
	mockRepo, _, svc := setupUserService()

	existingUser := &domain.User{ID: uuid.New(), Email: "john@example.com"}
	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(existingUser, nil)

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "securepassword",
	})

	assert.ErrorIs(t, err, domain.ErrEmailAlreadyInUse)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Login_Success(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	userID := uuid.New()
	hashedPW, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)

	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(&domain.User{
		ID:           userID,
		Name:         "John Doe",
		Email:        "john@example.com",
		PasswordHash: string(hashedPW),
	}, nil)

	resp, err := svc.Login(context.Background(), domain.LoginRequest{
		Email:    "john@example.com",
		Password: "correctpassword",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, userID, resp.User.ID)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Login_InvalidCredentials(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	hashedPW, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)

	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(&domain.User{
		ID:           uuid.New(),
		Email:        "john@example.com",
		PasswordHash: string(hashedPW),
	}, nil)

	resp, err := svc.Login(context.Background(), domain.LoginRequest{
		Email:    "john@example.com",
		Password: "wrongpassword",
	})

	assert.ErrorIs(t, err, domain.ErrInvalidCreds)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Login_UserNotFound(t *testing.T) {
	mockRepo, _, svc := setupUserService()

	mockRepo.On("GetByEmail", mock.Anything, "notfound@example.com").Return(nil, domain.ErrNotFound)

	resp, err := svc.Login(context.Background(), domain.LoginRequest{
		Email:    "notfound@example.com",
		Password: "anypassword",
	})

	assert.ErrorIs(t, err, domain.ErrInvalidCreds)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestUserService_GetProfile_Success(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	userID := uuid.New()

	mockRepo.On("GetByID", mock.Anything, userID).Return(&domain.User{
		ID:    userID,
		Name:  "John Doe",
		Email: "john@example.com",
	}, nil)

	user, err := svc.GetProfile(context.Background(), userID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "John Doe", user.Name)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_NormalizesEmail(t *testing.T) {
	mockRepo, _, svc := setupUserService()

	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(nil, domain.ErrNotFound)
	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
		return u.Email == "john@example.com" && u.Role == domain.RoleUser
	})).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(1).(*domain.User)
		u.ID = uuid.New()
	})

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "  John@Example.COM ",
		Password: "securepassword",
	})

	assert.NoError(t, err)
	assert.Equal(t, "john@example.com", resp.User.Email)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_PreservesRepositoryFailure(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	repositoryErr := errors.New("database unavailable")
	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(nil, repositoryErr)

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "securepassword",
	})

	assert.Error(t, err)
	assert.ErrorIs(t, err, repositoryErr)
	assert.NotErrorIs(t, err, domain.ErrEmailAlreadyInUse)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_MapsUniqueConflict(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	mockRepo.On("GetByEmail", mock.Anything, "john@example.com").Return(nil, domain.ErrNotFound)
	mockRepo.On("Create", mock.Anything, mock.Anything).Return(domain.ErrEmailAlreadyInUse)

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "securepassword",
	})

	assert.ErrorIs(t, err, domain.ErrEmailAlreadyInUse)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_RejectsPasswordOverBcryptByteLimit(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	password := strings.Repeat("é", 37) // 74 UTF-8 bytes.

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: password,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidInput)
	assert.Nil(t, resp)
	mockRepo.AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
}

func TestUserService_RefreshUsesCurrentDatabaseRole(t *testing.T) {
	mockRepo, tokenMgr, svc := setupUserService()
	userID := uuid.New()
	pair, err := tokenMgr.IssueTokens(context.Background(), userID, domain.RoleUser)
	assert.NoError(t, err)

	mockRepo.On("GetByID", mock.Anything, userID).Return(&domain.User{
		ID:    userID,
		Email: "owner@example.com",
		Role:  domain.RoleAdmin,
	}, nil)

	resp, err := svc.Refresh(context.Background(), pair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, resp.User.Role)
	claims, err := tokenMgr.ValidateAccessToken(context.Background(), resp.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, claims.Role)
}

func TestUserService_RefreshDoesNotConsumeTokenWhenDatabaseFails(t *testing.T) {
	mockRepo, tokenMgr, svc := setupUserService()
	userID := uuid.New()
	pair, err := tokenMgr.IssueTokens(context.Background(), userID, domain.RoleUser)
	assert.NoError(t, err)

	databaseErr := errors.New("database unavailable")
	mockRepo.On("GetByID", mock.Anything, userID).Return(nil, databaseErr)

	resp, err := svc.Refresh(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, databaseErr)
	assert.Nil(t, resp)

	_, err = tokenMgr.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	assert.NoError(t, err)
}

func TestUserService_RefreshMapsSessionStoreOutageToUnavailable(t *testing.T) {
	mockRepo := new(MockUserRepo)
	tokenMgr := auth.NewTokenManager("test-secret-key", 15*time.Minute, time.Hour, unavailableSessionStore{})
	svc := NewUserService(mockRepo, tokenMgr)
	pair, err := tokenMgr.IssueTokens(context.Background(), uuid.New(), domain.RoleUser)
	assert.NoError(t, err)

	resp, err := svc.Refresh(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, domain.ErrUnavailable)
	assert.Nil(t, resp)
}

type unavailableSessionStore struct{}

func (unavailableSessionStore) Create(context.Context, auth.Session) error { return nil }
func (unavailableSessionStore) Get(context.Context, string) (auth.Session, bool, error) {
	return auth.Session{}, false, errors.New("session store unavailable")
}
func (unavailableSessionStore) Revoke(context.Context, string) error {
	return errors.New("session store unavailable")
}
func (unavailableSessionStore) Rotate(context.Context, string, string, auth.Session) (auth.RotationStatus, error) {
	return auth.RotationRejected, errors.New("session store unavailable")
}

func TestUserService_GetProfile_NotFound(t *testing.T) {
	mockRepo, _, svc := setupUserService()
	userID := uuid.New()

	mockRepo.On("GetByID", mock.Anything, userID).Return(nil, domain.ErrNotFound)

	user, err := svc.GetProfile(context.Background(), userID)

	assert.ErrorIs(t, err, domain.ErrNotFound)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}
