package usecase

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/mohamedsalahi/GO_DB/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestProvisionAdminCreatesExplicitAdmin(t *testing.T) {
	repo := new(MockUserRepo)
	repo.On("GetByEmail", mock.Anything, "admin@example.com").Return(nil, domain.ErrNotFound)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(user *domain.User) bool {
		return user.Email == "admin@example.com" && user.Role == domain.RoleAdmin
	})).Return(nil).Run(func(args mock.Arguments) {
		user := args.Get(1).(*domain.User)
		user.ID = uuid.New()
	})

	admin, err := ProvisionAdmin(context.Background(), repo, " Admin@Example.com ", "Owner", "a sufficiently long password")
	assert.NoError(t, err)
	assert.Equal(t, "admin@example.com", admin.Email)
	assert.Equal(t, domain.RoleAdmin, admin.Role)
	repo.AssertExpectations(t)
}

func TestProvisionAdminRejectsInvalidIdentity(t *testing.T) {
	repo := new(MockUserRepo)

	admin, err := ProvisionAdmin(context.Background(), repo, "Owner <admin@example.com>", "Owner", "a sufficiently long password")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
	assert.Nil(t, admin)

	admin, err = ProvisionAdmin(context.Background(), repo, "admin@example.com", "Owner", "short")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
	assert.Nil(t, admin)

	repo.AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestProvisionAdminNeverPromotesExistingAccount(t *testing.T) {
	repo := new(MockUserRepo)
	existing := &domain.User{ID: uuid.New(), Email: "admin@example.com", Role: domain.RoleUser}
	repo.On("GetByEmail", mock.Anything, "admin@example.com").Return(existing, nil)

	admin, err := ProvisionAdmin(context.Background(), repo, "admin@example.com", "Owner", "a sufficiently long password")
	assert.ErrorIs(t, err, domain.ErrEmailAlreadyInUse)
	assert.Nil(t, admin)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
