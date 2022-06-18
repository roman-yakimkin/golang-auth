package tokenmanager

import "auth/internal/app/models"

type TokenManager interface {
	GenerateAccessToken(u *models.User) (string, error)
	GenerateRefreshToken(u *models.User) (string, error)
	ParseAccessToken(token string) (*AccessClaims, error)
	ParseRefreshToken(token string) (*RefreshClaims, error)
}
