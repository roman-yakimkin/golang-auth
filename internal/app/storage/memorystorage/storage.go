package memorystorage

import (
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/passwordmanager"
	"auth/internal/app/services/tokenmanager"
	"time"
)

type expiredRefreshToken struct {
	token   string
	expired int64
}

type Storage struct {
	roles     []models.Role
	users     []models.User
	expiredRT []expiredRefreshToken
	pm        passwordmanager.PasswordManager
	config    *configmanager.Config
	tm        tokenmanager.TokenManager
}

func NewStorage(pm passwordmanager.PasswordManager, config *configmanager.Config, tm tokenmanager.TokenManager) *Storage {
	return &Storage{
		pm:     pm,
		config: config,
		tm:     tm,
	}
}

func (s *Storage) Init() {
	for _, role := range s.config.Roles {
		s.roles = append(s.roles, models.Role{
			ID:   role["id"].(string),
			Name: role["name"].(string),
		})
	}
	for _, user := range s.config.Users {
		var roles []string
		for _, role := range user["roles"].([]interface{}) {
			roles = append(roles, role.(string))
		}
		s.users = append(s.users, models.User{
			ID:       user["id"].(int),
			Username: user["username"].(string),
			Password: user["password"].(string),
			Roles:    roles,
		})
	}

	//psw1, _ := s.pm.EncodePassword("password1")
	//psw2, _ := s.pm.EncodePassword("password2")
	//psw3, _ := s.pm.EncodePassword("password3")
}

func (s *Storage) FindUserById(uid int) *models.User {
	for _, u := range s.users {
		if uid == u.ID {
			return &u
		}
	}
	return nil
}

func (s *Storage) FindUserByName(username string) *models.User {
	for _, u := range s.users {
		if username == u.Username {
			return &u
		}
	}
	return nil
}

func (s *Storage) FindUserByNameAndPassword(username string, password string) *models.User {
	for _, u := range s.users {
		if (u.Username == username) && s.pm.ComparePasswords(u.Password, password) {
			return &u
		}
	}
	return nil
}

func (s *Storage) MemorizeRefreshTokenIfExpired(token string) {
	claims, err := s.tm.ParseRefreshToken(token)
	if err != nil {
		return
	}
	s.expiredRT = append(s.expiredRT, expiredRefreshToken{
		token:   token,
		expired: claims.ExpiresAt,
	})
}

func (s *Storage) IsRefreshTokenExpired(token string) bool {
	claims, err := s.tm.ParseRefreshToken(token)
	return err != nil || s.refreshTokenInArray(token) || claims.ExpiresAt <= time.Now().Unix()
}

func (s *Storage) refreshTokenInArray(token string) bool {
	for _, refreshToken := range s.expiredRT {
		if refreshToken.token == token {
			return true
		}
	}
	return false
}

func (s *Storage) CleanExpiredRefreshTokens() {
	newArray := make([]expiredRefreshToken, len(s.expiredRT)/2)
	for _, expiredToken := range s.expiredRT {
		if expiredToken.expired > time.Now().Unix() {
			s.expiredRT = append(s.expiredRT, expiredToken)
		}
	}
	s.expiredRT = newArray
}
