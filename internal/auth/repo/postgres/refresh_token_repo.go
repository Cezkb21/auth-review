package postgres

import (
	"context"
	"errors"
	"pawsy/internal/auth/domain"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool}
}

func (r *RefreshTokenRepo) Create(ctx context.Context, token *domain.RefreshTokenModel) error {
	sqlQuery := `
	INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, revoked_at, created_at)
	VALUES ($1, $2, $3, $4, $5, $6);
	`
	_, err := r.pool.Exec(ctx, sqlQuery, token.ID, token.UserID, token.HashedToken, token.ExpiresAt, token.RevokedAt, token.CreatedAt)
	return err
}

func (r *RefreshTokenRepo) Get(ctx context.Context, hashedToken string) (*domain.RefreshTokenModel, error) {
	sqlQuery := `
	SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
	FROM refresh_tokens 
	WHERE token_hash = $1;
	`
	var token domain.RefreshTokenModel
	err := r.pool.QueryRow(ctx, sqlQuery, hashedToken).Scan(
		&token.ID,
		&token.UserID,
		&token.HashedToken,
		&token.ExpiresAt,
		&token.RevokedAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenNotFound
		}
		return nil, err
	}
	return &token, nil

}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, hashedToken string) error {
	sqlQuery := `
	UPDATE refresh_tokens
	SET revoked_at = $1
	WHERE token_hash = $2;
	`

	_, err := r.pool.Exec(ctx, sqlQuery, time.Now(), hashedToken)
	return err
}

func (r *RefreshTokenRepo) RevokeAll(ctx context.Context, userID string) error {
	sqlQuery := `
	UPDATE refresh_tokens
	SET revoked_at = $1
	WHERE user_id = $2 AND revoked_at IS NULL;
	`

	_, err := r.pool.Exec(ctx, sqlQuery, time.Now(), userID)
	return err
}
