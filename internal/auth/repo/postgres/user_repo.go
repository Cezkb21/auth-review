package postgres

import (
	"context"
	"errors"
	"pawsy/internal/auth/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	sqlQuery := `
	INSERT INTO users (id, email, hashed_password, role, created_at) 
	VALUES ($1, $2, $3, $4, $5);
	`
	_, err := r.pool.Exec(ctx, sqlQuery, u.ID, u.Email, u.HashedPassword, u.Role, u.CreatedAt)
	return err
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	sqlQuery := `
	SELECT id, email, hashed_password, role, created_at 
	FROM users 
	WHERE email = $1;
	`
	var user domain.User
	err := r.pool.QueryRow(ctx, sqlQuery, email).Scan(
		&user.ID,
		&user.Email,
		&user.HashedPassword,
		&user.Role,
		&user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepo) FindRoleByUserID(ctx context.Context, userID string) (role string, err error) {
	sqlQuery := `
	SELECT role
	FROM users 
	WHERE id = $1;
	`
	err = r.pool.QueryRow(ctx, sqlQuery, userID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", domain.ErrUserNotFound
		}
		return "", err
	}
	return role, nil
}

func (r *UserRepo) Update(ctx context.Context, u *domain.User) error {
	sqlQuery := `
	UPDATE users
	SET email = $1, hashed_password = $2, role = $3
	WHERE id = $4;
	`

	_, err := r.pool.Exec(ctx, sqlQuery, u.Email, u.HashedPassword, u.Role, u.ID)
	return err
}
