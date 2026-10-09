package mocks

import (
	"context"
)

type MockUserCache struct {
	MockUserRepo
}

func (m *MockUserCache) CreateRoleByID(ctx context.Context, testUserID, testRole string) error {
	args := m.Called(ctx, testUserID, testRole)
	return args.Error(0)
}
