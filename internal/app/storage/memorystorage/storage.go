package memorystorage

import (
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/passwordmanager"
)

type Storage struct {
	roles  []models.Role
	users  []models.User
	pm     passwordmanager.PasswordManager
	config *configmanager.Config
}

func NewStorage(pm passwordmanager.PasswordManager, config *configmanager.Config) *Storage {
	return &Storage{
		pm:     pm,
		config: config,
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
