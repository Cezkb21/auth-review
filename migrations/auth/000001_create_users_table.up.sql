CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       email TEXT NOT NULL UNIQUE,
                       hashed_password TEXT NOT NULL,
                       role TEXT DEFAULT 'userID',
                       created_at TIMESTAMP DEFAULT NOW()
);