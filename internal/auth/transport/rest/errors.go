package rest

import (
	"errors"
	"net/http"
	"pawsy/internal/auth/app/security"
	"pawsy/internal/auth/domain"
)

func HTTPStatusFromError(err error) int {
	switch {
	case errors.Is(err, domain.ErrUserInvalidCredentials),
		errors.Is(err, security.ErrInvalidToken),
		errors.Is(err, security.ErrTokenExpired):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrTokenRevoked),
		errors.Is(err, domain.ErrTokenNotFound),
		errors.Is(err, security.ErrUserIDNotMatch):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrUserAlreadyExists):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
