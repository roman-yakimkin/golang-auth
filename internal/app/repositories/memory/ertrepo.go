package memory

import (
	"auth/internal/app/interfaces"
	"auth/internal/app/models"
	"time"
)

type ExpiredRefreshTokenRepo struct {
	tokens map[string]models.ExpiredRefreshToken
	tm     interfaces.TokenManager
}

func NewExpiredrefreshTokenRepo() *ExpiredRefreshTokenRepo {
	return &ExpiredRefreshTokenRepo{}
}

func (r *ExpiredRefreshTokenRepo) MemorizeIfExpired(token string) error {
	claims, err := r.tm.ParseRefreshToken(token)
	if err != nil {
		return err
	}
	r.tokens[token] = models.ExpiredRefreshToken{
		Token:   token,
		Expired: claims.ExpiresAt,
	}
	return nil
}

func (r *ExpiredRefreshTokenRepo) IsExpired(token string) (bool, error) {
	claims, err := r.tm.ParseRefreshToken(token)
	if err != nil {
		return false, err
	}
	_, ok := r.tokens[token]

	return ok || claims.ExpiresAt <= time.Now().Unix(), nil
}

func (r *ExpiredRefreshTokenRepo) Clean() error {
	for name, token := range r.tokens {
		if token.Expired <= time.Now().Unix() {
			delete(r.tokens, name)
		}
	}
	return nil
}
