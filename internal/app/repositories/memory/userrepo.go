package memory

import (
	"auth/internal/app/errors"
	"auth/internal/app/interfaces"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
)

type UserRepo struct {
	users  map[int]models.User
	pm     interfaces.PasswordManager
	config *configmanager.Config
}

func NewUserRepo(pm interfaces.PasswordManager, config *configmanager.Config) *UserRepo {
	users := make(map[int]models.User)
	for _, user := range config.Users {
		var roles []string
		for _, role := range user["roles"].([]interface{}) {
			roles = append(roles, role.(string))
		}
		key := user["id"].(int)
		users[key] = models.User{
			ID:       key,
			Username: user["username"].(string),
			Password: user["password"].(string),
			Roles:    roles,
		}
	}
	repo := UserRepo{
		users:  users,
		pm:     pm,
		config: config,
	}

	return &repo
}

func (r *UserRepo) GetByID(uid int) (*models.User, error) {
	u, ok := r.users[uid]
	if !ok {
		return nil, errors.ErrUserNotFound
	}
	return &u, nil
}

func (r *UserRepo) GetByName(name string) (*models.User, error) {
	for _, u := range r.users {
		if u.Username == name {
			return &u, nil
		}
	}
	return nil, errors.ErrUserNotFound
}

func (r *UserRepo) GetByNameAndPassword(name string, password string) (*models.User, error) {
	for _, u := range r.users {
		if u.Username == name && r.pm.ComparePasswords(u.Password, password) {
			return &u, nil
		}
	}
	return nil, errors.ErrUserNotFound
}
