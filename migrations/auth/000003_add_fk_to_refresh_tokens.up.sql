ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user_id
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE;