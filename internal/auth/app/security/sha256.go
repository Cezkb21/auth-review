package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"pawsy/pkg/config"
)

type TokenHasher struct {
	salt []byte
}

func NewTokenHasher(cfg config.SHA256Config) *TokenHasher {
	return &TokenHasher{
		salt: cfg.Salt,
	}
}

func (h *TokenHasher) Hash(token string) (string, error) {

	if _, err := rand.Read(h.salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	hash := sha256.Sum256(append([]byte(token), h.salt...))
	return base64.StdEncoding.EncodeToString(h.salt) + "$" + base64.StdEncoding.EncodeToString(hash[:]), nil
}

func (h *TokenHasher) Verify(token, stored string) (bool, error) {
	return false, errors.New("not implemented")
}
