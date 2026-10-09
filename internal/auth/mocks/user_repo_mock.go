package mocks

import (
	"context"
	"pawsy/internal/auth/domain"

	"github.com/stretchr/testify/mock"
)

type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) FindByEmail(ctx context.Context, testEmail string) (*domain.User, error) {
	args := m.Called(ctx, testEmail)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepo) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepo) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepo) FindRoleByUserID(ctx context.Context, testUserID string) (string, error) {
	args := m.Called(ctx, testUserID)
	return args.String(0), args.Error(1)
}
