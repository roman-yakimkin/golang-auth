package mongo

import (
	"auth/internal/app/interfaces"
	"auth/internal/app/repositories/mongo"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/dbclient"
)

type Store struct {
	userRepo *mongo.UserRepo
	roleRepo *mongo.RoleRepo
	ertRepo  *mongo.ExpiredRefreshTokenRepo
	pm       interfaces.PasswordManager
	config   *configmanager.Config
	tm       interfaces.TokenManager
	db       *dbclient.MongoDBClient
}

func NewStore(
	userRepo *mongo.UserRepo,
	roleRepo *mongo.RoleRepo,
	ertRepo *mongo.ExpiredRefreshTokenRepo,
	pm interfaces.PasswordManager,
	config *configmanager.Config,
	tm interfaces.TokenManager,
	db *dbclient.MongoDBClient) *Store {
	return &Store{
		userRepo: userRepo,
		roleRepo: roleRepo,
		ertRepo:  ertRepo,
		pm:       pm,
		config:   config,
		tm:       tm,
		db:       db,
	}
}

func (s *Store) User() interfaces.UserRepo {
	if s.userRepo == nil {
		s.userRepo = mongo.NewUserRepo(s.pm, s.config, s.db)
	}
	return s.userRepo
}

func (s *Store) Role() interfaces.RoleRepo {
	if s.roleRepo == nil {
		s.roleRepo = mongo.NewRoleRepo(s.config, s.db)
	}
	return s.roleRepo
}

func (s *Store) ExpiredRT() interfaces.ExpiredRefreshTokenRepo {
	if s.ertRepo == nil {
		s.ertRepo = mongo.NewExpiredRefreshTokenRepo(s.tm, s.db)
	}
	return s.ertRepo
}
