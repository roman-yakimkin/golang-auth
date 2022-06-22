package memory

import (
	"auth/internal/app/interfaces"
	"auth/internal/app/repositories/memory"
	"auth/internal/app/services/configmanager"
)

type Store struct {
	userRepo *memory.UserRepo
	roleRepo *memory.RoleRepo
	ertRepo  *memory.ExpiredRefreshTokenRepo
	pm       interfaces.PasswordManager
	config   *configmanager.Config
	tm       interfaces.TokenManager
}

func NewStore(
	userRepo *memory.UserRepo,
	roleRepo *memory.RoleRepo,
	ertRepo *memory.ExpiredRefreshTokenRepo,
	pm interfaces.PasswordManager,
	config *configmanager.Config,
	tm interfaces.TokenManager) *Store {
	return &Store{
		userRepo: userRepo,
		roleRepo: roleRepo,
		ertRepo:  ertRepo,
		pm:       pm,
		config:   config,
		tm:       tm,
	}
}

func (s *Store) User() interfaces.UserRepo {
	if s.userRepo == nil {
		s.userRepo = memory.NewUserRepo(s.pm, s.config)
	}
	return s.userRepo
}

func (s *Store) Role() interfaces.RoleRepo {
	if s.roleRepo == nil {
		s.roleRepo = &memory.RoleRepo{}
	}
	return s.roleRepo
}

func (s *Store) ExpiredRT() interfaces.ExpiredRefreshTokenRepo {
	if s.ertRepo == nil {
		s.ertRepo = &memory.ExpiredRefreshTokenRepo{}
	}
	return s.ertRepo
}
