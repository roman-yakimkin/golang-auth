package memorystorage_test

import (
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/passwordmanager"
	"auth/internal/app/services/tokenmanager"
	"auth/internal/app/storage/memorystorage"
	"flag"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStorage_FindUserById(t *testing.T) {
	flag.Parse()
	config := configmanager.NewConfig()
	err := config.Init("config_test.yml")
	if err != nil {
		t.Fatal("config init fail", err)
	}
	pm := passwordmanager.BCryptPasswordManager{}
	tm := tokenmanager.NewJWTTokenManager(config)
	storage := memorystorage.NewStorage(&pm, config, tm)
	storage.Init()

	testCases := []struct {
		name    string
		uid     int
		result  func() *models.User
		isValid bool
	}{
		{
			name: "valid user 1",
			uid:  1,
			result: func() *models.User {
				return &models.User{
					ID:       1,
					Username: "user1",
					Password: "$2a$10$OgcMhbZH5BX5cXssxeGz5uNbjLSStpp76lnUMQqLbV8bZwGzOm/va",
					Roles:    []string{"task_creator", "authenticated"},
				}
			},
			isValid: true,
		},
		{
			name: "valid user2",
			uid:  2,
			result: func() *models.User {
				return &models.User{
					ID:       2,
					Username: "user2",
					Password: "$2a$10$fWVsdKGXuOxMzL0tahrd2./BjJHasZ7QvdGJWjtpbV0aUbswVmdhC",
					Roles:    []string{"analyst", "authenticated"},
				}
			},
			isValid: true,
		},
		{
			name: "user with invalid params",
			uid:  3,
			result: func() *models.User {
				return &models.User{
					ID:       2,
					Username: "user333",
					Password: "$2a$10$fWVsdKGXuOxMzL0tahrd2./BjJHasZ7QvdGJWjtpbV0aUbswVmdhC",
					Roles:    []string{"authenticated"},
				}
			},
			isValid: false,
		},
		{
			name: "user is absent",
			uid:  10,
			result: func() *models.User {
				return nil
			},
			isValid: true,
		},
	}

	for _, tc := range testCases {
		actual := storage.FindUserById(tc.uid)
		expect := tc.result()
		if tc.isValid {
			assert.Equal(t, expect, actual, tc.name)
		} else {
			assert.NotEqual(t, expect, actual, tc.name)
		}
	}
}
