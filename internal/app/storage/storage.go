package storage

import "auth/internal/app/models"

type Storage interface {
	Init()
	FindUserById(int) *models.User
	FindUserByName(string) *models.User
	FindUserByNameAndPassword(string, string) *models.User
}
