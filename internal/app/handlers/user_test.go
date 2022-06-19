package handlers_test

import (
	"auth/internal/app/handlers"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/passwordmanager"
	"auth/internal/app/services/tokenmanager"
	"auth/internal/app/storage/memorystorage"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUserController_UserLogin(t *testing.T) {
	config := configmanager.NewConfig()
	err := config.Init("config_test.yml")
	if err != nil {
		t.Fatal("config init fail", err)
	}
	pm := passwordmanager.BCryptPasswordManager{}
	tm := tokenmanager.NewJWTTokenManager(config)
	storage := memorystorage.NewStorage(&pm, config, tm)
	storage.Init()

	userCtrl := handlers.NewUserController(storage, tm, config)
	mw := handlers.NewMiddleware(tm)

	router := mux.NewRouter()
	router.HandleFunc("/login", userCtrl.UserLogin).Methods("POST")
	router.Use(mw.Logging)

	testCases := []struct {
		name            string
		payload         interface{}
		expectedCookies func() map[string]http.Cookie
		expectedCode    int
	}{
		{
			name: "valid",
			payload: map[string]string{
				"login":    "user1",
				"password": "password1",
			},
			expectedCookies: func() map[string]http.Cookie {
				result := make(map[string]http.Cookie)
				result["access_token"] = http.Cookie{
					Name:    "access_token",
					Value:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTU2NDY1NzQsImlhdCI6MTY1NTY0NjU2OSwiVXNlcm5hbWUiOiJ1c2VyMSIsIlJvbGVzIjpbInRhc2tfY3JlYXRvciIsImF1dGhlbnRpY2F0ZWQiXX0._6lOuXYbeI9fydiaHUUqAgFPU9lAugRrZv3FiTM42Kg",
					Expires: time.Now().Add(time.Hour),
				}
				result["refresh_token"] = http.Cookie{
					Name:    "refresh_token",
					Value:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTU2NTE0NzEsImlhdCI6MTY1NTY0Nzg3MSwiVXNlcm5hbWUiOiJ1c2VyMSJ9.vncBUYoLYjWKSuX1ToakmGwjbzHYPHH8YxqnXfkWMMY",
					Expires: time.Now().Add(time.Hour),
				}
				return result
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "invalid password",
			payload: map[string]string{
				"login":    "user1",
				"password": "password1invalid",
			},
			expectedCookies: func() map[string]http.Cookie {
				return nil
			},
			expectedCode: http.StatusUnauthorized,
		},
	}
	for _, tc := range testCases {
		rec := httptest.NewRecorder()
		b := &bytes.Buffer{}
		json.NewEncoder(b).Encode(tc.payload)
		req, _ := http.NewRequest("POST", "/login", b)
		router.ServeHTTP(rec, req)

		var result map[string]interface{}
		json.NewDecoder(rec.Body).Decode(&result)
		fmt.Println(result)

		assert.Equal(t, tc.expectedCode, rec.Code)
	}
}
