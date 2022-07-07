package server

import (
	"auth/internal/app/errors"
	"auth/internal/app/grpc/api"
	"auth/internal/app/interfaces"
	"context"
	"strings"
)

type GRPCServer struct {
	store interfaces.Store
	tm    interfaces.TokenManager
}

func NewGRPCServer(store interfaces.Store, tm interfaces.TokenManager) *GRPCServer {
	return &GRPCServer{
		store: store,
		tm:    tm,
	}
}

func (s *GRPCServer) Validate(ctx context.Context, req *api.ValidateRequest) (*api.ValidateResponse, error) {
	accessClaims, err := s.tm.ParseAccessToken(req.GetAccessToken())
	if err == nil {
		// Access token is valid
		user, err := s.store.User().GetByName(accessClaims.Username)
		if err != nil {
			return nil, err
		}
		return &api.ValidateResponse{
			UserId:       user.ID,
			Roles:        user.Roles,
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
		}, nil
	}
	if strings.Contains(err.Error(), "token is expired") {
		// Refresh token invalid or expired
		refreshClaims, err := s.tm.ParseRefreshToken(req.GetRefreshToken())
		if err != nil {
			return nil, err
		}
		exp, err := s.store.ExpiredRT().IsExpired(req.GetRefreshToken())
		if exp || err != nil {
			return nil, errors.ErrInvalidRefreshToken
		}

		// Refresh token is valid, get user data from refresh token and
		user, err := s.store.User().GetByName(refreshClaims.Username)
		if err != nil {
			return nil, err
		}
		newAccessToken, err := s.tm.GenerateAccessToken(user)
		if err != nil {
			return nil, err
		}
		newRefreshToken, err := s.tm.GenerateRefreshToken(user)
		return &api.ValidateResponse{
			UserId:       user.ID,
			Roles:        user.Roles,
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
		}, nil
	}
	return nil, err
}
