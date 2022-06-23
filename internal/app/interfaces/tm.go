package interfaces

import (
	"auth/internal/app/models"
	"github.com/dgrijalva/jwt-go"
)

type AccessClaims struct {
	jwt.StandardClaims
	Username string
	Roles    []string
}

type RefreshClaims struct {
	jwt.StandardClaims
	Username string
}

type TokenManager interface {
	GenerateAccessToken(u *models.User) (string, error)
	GenerateRefreshToken(u *models.User) (string, error)
	ParseAccessToken(token string) (*AccessClaims, error)
	ParseRefreshToken(token string) (*RefreshClaims, error)
}
