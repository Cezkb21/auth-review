
CREATE TABLE refresh_tokens (
                                id UUID PRIMARY KEY,
                                user_id UUID NOT NULL,
                                token_hash TEXT NOT NULL UNIQUE,
                                expires_at TIMESTAMP NOT NULL,
                                revoked_at TIMESTAMP,
                                created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_id ON refresh_tokens(token_hash);