package interfaces

import "auth/internal/app/models"

type RoleRepo interface {
	GetByID(string) (*models.Role, error)
	GetByName(string) (*models.Role, error)
}
