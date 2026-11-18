package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/Sifr-Dev/mizan/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

const (
	minimumAdminPasswordBytes       = 12
	minimumAdminPasswordRunes       = 12
	maximumAdminBcryptPasswordBytes = 72
	maximumAdminNameRunes           = 100
	maximumEmailLength              = 255
)

// ProvisionAdmin creates one explicitly requested administrator. It never
// promotes an existing account and is intentionally separate from application
// startup.
func ProvisionAdmin(ctx context.Context, userRepo domain.UserRepository, email, name, password string) (*domain.User, error) {
	email = domain.NormalizeEmail(email)
	name = strings.TrimSpace(name)
	if err := validateAdminIdentity(email, name, password); err != nil {
		return nil, err
	}

	existing, err := userRepo.GetByEmail(ctx, email)
	if err == nil && existing != nil {
		return nil, domain.ErrEmailAlreadyInUse
	}
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("check administrator email: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash administrator password: %w", err)
	}

	admin := &domain.User{
		Name:         name,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Role:         domain.RoleAdmin,
	}
	if err := userRepo.Create(ctx, admin); err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyInUse) {
			return nil, domain.ErrEmailAlreadyInUse
		}
		return nil, fmt.Errorf("create administrator: %w", err)
	}
	return admin, nil
}

func validateAdminIdentity(email, name, password string) error {
	if email == "" || len(email) > maximumEmailLength {
		return fmt.Errorf("%w: administrator email is invalid", domain.ErrInvalidInput)
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Name != "" || parsed.Address != email {
		return fmt.Errorf("%w: administrator email is invalid", domain.ErrInvalidInput)
	}
	if name == "" || utf8.RuneCountInString(name) > maximumAdminNameRunes {
		return fmt.Errorf("%w: administrator name must contain between 1 and %d characters", domain.ErrInvalidInput, maximumAdminNameRunes)
	}
	if len([]byte(password)) < minimumAdminPasswordBytes || utf8.RuneCountInString(password) < minimumAdminPasswordRunes {
		return fmt.Errorf("%w: administrator password must be at least %d characters and %d bytes", domain.ErrInvalidInput, minimumAdminPasswordRunes, minimumAdminPasswordBytes)
	}
	if len([]byte(password)) > maximumAdminBcryptPasswordBytes {
		return fmt.Errorf("%w: administrator password must not exceed %d bytes", domain.ErrInvalidInput, maximumAdminBcryptPasswordBytes)
	}
	return nil
}
