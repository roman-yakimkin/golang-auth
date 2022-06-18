package main

import (
	"auth/internal/app/handlers"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/passwordmanager"
	"auth/internal/app/services/tokenmanager"
	"auth/internal/app/storage/memorystorage"
	"flag"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config-path", "config/config.yml", "path to config file")
}

func main() {
	flag.Parse()
	config := configmanager.NewConfig()
	err := config.Init(configPath)
	if err != nil {
		log.Fatal(err)
	}

	pm := passwordmanager.BCryptPasswordManager{}
	tm := tokenmanager.NewJWTTokenManager(config)
	storage := memorystorage.NewStorage(&pm, config, tm)
	storage.Init()
	userCtrl := handlers.NewUserController(storage, tm, config)

	mw := handlers.NewMiddleware(tm)

	router := mux.NewRouter()

	router.HandleFunc("/login", userCtrl.UserLogin).Methods("POST")
	router.HandleFunc("/logout", userCtrl.UserLogout).Methods("POST")

	router.HandleFunc("/refresh-token", userCtrl.UserRefreshToken).Methods("POST")
	router.HandleFunc("/i", userCtrl.UserInfo).Methods("GET")

	router.Use(mw.Logging)

	err = http.ListenAndServe(config.BindAddr, router)
	log.Fatal(err)
}
