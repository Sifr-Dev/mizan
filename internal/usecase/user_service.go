package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/Sifr-Dev/GO_DB/internal/domain"
	"github.com/Sifr-Dev/GO_DB/internal/infra/auth"
	"golang.org/x/crypto/bcrypt"
)

const maximumBcryptPasswordBytes = 72

type userService struct {
	userRepo domain.UserRepository
	tokenMgr *auth.TokenManager
}

func NewUserService(userRepo domain.UserRepository, tokenMgr *auth.TokenManager) domain.UserService {
	return &userService{
		userRepo: userRepo,
		tokenMgr: tokenMgr,
	}
}

func (s *userService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.AuthResponse, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Email = domain.NormalizeEmail(req.Email)
	if err := validatePasswordBytes(req.Password); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, domain.ErrEmailAlreadyInUse
	}
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &domain.User{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         domain.RoleUser,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyInUse) {
			return nil, domain.ErrEmailAlreadyInUse
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return s.issueResponse(ctx, user)
}

func (s *userService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	req.Email = domain.NormalizeEmail(req.Email)
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidCreds
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, domain.ErrInvalidCreds
	}
	if user.Role == "" {
		user.Role = domain.RoleUser
	}

	return s.issueResponse(ctx, user)
}

func (s *userService) Refresh(ctx context.Context, refreshToken string) (*domain.AuthResponse, error) {
	claims, err := s.tokenMgr.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrSessionUnavailable) {
			return nil, fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		if errors.Is(err, auth.ErrSessionRevoked) || errors.Is(err, auth.ErrRefreshTokenReused) || errors.Is(err, auth.ErrInvalidToken) {
			return nil, domain.ErrInvalidCreds
		}
		return nil, fmt.Errorf("validate refresh token: %w", err)
	}

	// Resolve the account and its current role before consuming the refresh
	// token. A transient database failure must not burn the browser session.
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidCreds
		}
		return nil, fmt.Errorf("get refreshed user: %w", err)
	}
	if user.Role == "" {
		user.Role = domain.RoleUser
	}

	pair, err := s.tokenMgr.RefreshTokens(ctx, refreshToken, user.Role)
	if err != nil {
		if errors.Is(err, auth.ErrSessionUnavailable) {
			return nil, fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		if errors.Is(err, auth.ErrSessionRevoked) || errors.Is(err, auth.ErrRefreshTokenReused) || errors.Is(err, auth.ErrInvalidToken) {
			return nil, domain.ErrInvalidCreds
		}
		return nil, fmt.Errorf("refresh tokens: %w", err)
	}

	return &domain.AuthResponse{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		RefreshExpiresAt: pair.RefreshExpiresAt,
		User:             *user,
	}, nil
}

func (s *userService) Logout(ctx context.Context, refreshToken string) error {
	if strings.TrimSpace(refreshToken) == "" {
		return nil
	}
	if err := s.tokenMgr.RevokeRefreshToken(ctx, refreshToken); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrSessionRevoked) {
			return nil
		}
		if errors.Is(err, auth.ErrSessionUnavailable) {
			return fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func (s *userService) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return user, nil
}

func (s *userService) issueResponse(ctx context.Context, user *domain.User) (*domain.AuthResponse, error) {
	pair, err := s.tokenMgr.IssueTokens(ctx, user.ID, user.Role)
	if err != nil {
		if errors.Is(err, auth.ErrSessionUnavailable) {
			return nil, fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		return nil, fmt.Errorf("issue authentication tokens: %w", err)
	}
	return &domain.AuthResponse{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		RefreshExpiresAt: pair.RefreshExpiresAt,
		User:             *user,
	}, nil
}

func validatePasswordBytes(password string) error {
	if len([]byte(password)) > maximumBcryptPasswordBytes {
		return fmt.Errorf("%w: password must not exceed %d bytes", domain.ErrInvalidInput, maximumBcryptPasswordBytes)
	}
	return nil
}
