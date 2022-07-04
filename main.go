package main

import (
	"auth/internal/app/handlers"
	"auth/internal/app/repositories/mongo"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/dbclient"
	"auth/internal/app/services/passwordmanager"
	"auth/internal/app/services/tokenmanager"
	mongo2 "auth/internal/app/store/mongo"
	"flag"
	"net/http"
	"net/http/pprof"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config-path", "config/config.yml", "path to config file")
}

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	flag.Parse()
	config := configmanager.NewConfig()
	err := config.Init(configPath)
	if err != nil {
		log.Fatal().Err(err)
	}

	pm := passwordmanager.BCryptPasswordManager{}
	tm := tokenmanager.NewJWTTokenManager(config)
	db := dbclient.NewMongoDBClient(config)
	userRepo := mongo.NewUserRepo(&pm, config, db)
	roleRepo := mongo.NewRoleRepo(config, db)
	ertRepo := mongo.NewExpiredRefreshTokenRepo(tm, db)
	store := mongo2.NewStore(userRepo, roleRepo, ertRepo, &pm, config, tm, db)
	userCtrl := handlers.NewUserController(store, tm, config)

	mw := handlers.NewMiddleware(tm)

	router := mux.NewRouter()

	router.HandleFunc("/login", userCtrl.UserLogin).Methods("POST")
	router.HandleFunc("/logout", userCtrl.UserLogout).Methods("POST")

	router.HandleFunc("/refresh-token", userCtrl.UserRefreshToken).Methods("POST")
	router.HandleFunc("/i", userCtrl.UserInfo).Methods("GET")

	router.HandleFunc("/pprof/", pprof.Index)
	router.HandleFunc("/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/pprof/profile", pprof.Profile)
	router.HandleFunc("/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/pprof/trace", pprof.Trace)
	router.Handle("/pprof/block", pprof.Handler("block"))
	router.Handle("/pprof/heap", pprof.Handler("heap"))
	router.Handle("/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/pprof/threadcreate", pprof.Handler("threadcreate"))

	router.Use(mw.Logging)

	err = http.ListenAndServe(config.BindAddr, router)
	log.Fatal().Err(err)
}
