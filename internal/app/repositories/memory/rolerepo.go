package memory

import (
	"auth/internal/app/errors"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"strconv"
)

type RoleRepo struct {
	roles  map[string]models.Role
	config *configmanager.Config
}

func NewRoleRepo(config *configmanager.Config) *RoleRepo {
	roles := make(map[string]models.Role)
	for i, role := range config.Roles {
		roleId := role["name"].(string)
		roles[roleId] = models.Role{
			ID:   strconv.Itoa(i + 1),
			Name: role["name"].(string),
			Desc: role["desc"].(string),
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
		return nil, errors.ErrRoleNotFound
	}
	return &role, nil
}

func (r *RoleRepo) GetByName(roleName string) (*models.Role, error) {
	for _, role := range r.roles {
		if role.Name == roleName {
			return &role, nil
		}
	}
	return nil, errors.ErrRoleNotFound
}
