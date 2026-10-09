package cache

import (
	"context"
	"pawsy/internal/auth/domain"
	"sync"
)

type UserCache struct {
	muAuth sync.RWMutex
	muRole sync.RWMutex

	usersAuth map[string]*domain.User
	usersRole map[string]string
}

func NewUserRepo() *UserCache {
	return &UserCache{
		usersAuth: make(map[string]*domain.User),
		usersRole: make(map[string]string),
	}
}

func (r *UserCache) Create(ctx context.Context, u *domain.User) error {
	r.muAuth.Lock()
	defer r.muAuth.Unlock()

	r.usersAuth[u.Email] = u

	r.muRole.Lock()
	defer r.muRole.Unlock()

	r.usersRole[u.ID] = u.Role

	return nil
}

func (r *UserCache) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.muAuth.RLock()
	defer r.muAuth.RUnlock()

	u, ok := r.usersAuth[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (r *UserCache) Update(ctx context.Context, u *domain.User) error {
	r.muAuth.Lock()
	defer r.muAuth.Unlock()

	r.usersAuth[u.Email] = u
	return nil
}

func (r *UserCache) FindRoleByUserID(ctx context.Context, userID string) (string, error) {
	r.muRole.RLock()
	defer r.muRole.RUnlock()

	role, ok := r.usersRole[userID]
	if !ok {
		return "", domain.ErrUserNotFound
	}
	return role, nil
}

func (r *UserCache) CreateRoleByID(ctx context.Context, userID, role string) error {
	r.muRole.Lock()
	defer r.muRole.Unlock()

	r.usersRole[userID] = role
	return nil
}
