package memory

import (
	"auth/internal/app/errors"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
)

type RoleRepo struct {
	roles  map[string]models.Role
	config *configmanager.Config
}

func NewRoleRepo(config *configmanager.Config) *RoleRepo {
	roles := make(map[string]models.Role)
	for _, role := range config.Roles {
		roleId := role["id"].(string)
		roles[roleId] = models.Role{
			ID:   roleId,
			Name: role["name"].(string),
		}
	}
	repo := RoleRepo{
		roles:  roles,
		config: config,
	}
	return &repo
}

func (r *RoleRepo) GetByID(roleId string) (*models.Role, error) {
	role, ok := r.roles[roleId]
	if !ok {
		return nil, errors.ErrUserNotFound
	}
	return &role, nil
}
