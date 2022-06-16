package storage

import "auth/internal/app/models"

type Storage interface {
	Init()
	FindUserById(int) (*models.User, error)
	FindUserByName(string) (*models.User, error)
	FindUserByNameAndPassword(string, string) (*models.User, error)
}
