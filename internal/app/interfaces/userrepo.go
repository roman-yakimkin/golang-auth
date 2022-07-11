package interfaces

import "auth/internal/app/models"

type UserRepo interface {
	GetByID(string) (*models.User, error)
	GetByName(string) (*models.User, error)
	GetByNameAndPassword(string, string) (*models.User, error)
}
