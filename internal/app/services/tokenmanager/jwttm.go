package tokenmanager

import (
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var JWTSecretKey []byte = []byte("secret")

type JWTTokenManager struct {
	config *configmanager.Config
}

func NewJWTTokenManager(config *configmanager.Config) *JWTTokenManager {
	return &JWTTokenManager{
		config: config,
	}
}

func (t *JWTTokenManager) GenerateAccessToken(u *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: GetExpireTime(t.config.JWTAccessTokenLifeTime).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Username: u.Username,
		Roles:    u.Roles,
	})
	tokenString, err := token.SignedString(JWTSecretKey)
	return tokenString, err
}

func (t *JWTTokenManager) GenerateRefreshToken(u *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, RefreshClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: GetExpireTime(t.config.JWTRefreshTokenLifeTime).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Username: u.Username,
	})
	tokenString, err := token.SignedString(JWTSecretKey)
	return tokenString, err
}

func (t *JWTTokenManager) ParseAccessToken(token string) (*AccessClaims, error) {
	tokenData, err := jwt.ParseWithClaims(token, &AccessClaims{}, func(jt *jwt.Token) (interface{}, error) {
		if _, ok := jt.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", jt.Header["alg"])
		}
		return JWTSecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := tokenData.Claims.(*AccessClaims); ok && tokenData.Valid {
		return claims, nil
	}
	return nil, ErrInvalidAccessToken
}

func (t *JWTTokenManager) ParseRefreshToken(token string) (*RefreshClaims, error) {
	tokenData, err := jwt.ParseWithClaims(token, &RefreshClaims{}, func(jt *jwt.Token) (interface{}, error) {
		if _, ok := jt.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", jt.Header["alg"])
		}
		return JWTSecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := tokenData.Claims.(*RefreshClaims); ok && tokenData.Valid {
		return claims, nil
	}
	return nil, ErrInvalidAccessToken
}
