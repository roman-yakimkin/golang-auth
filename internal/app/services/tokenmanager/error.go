package tokenmanager

import "errors"

var ErrInvalidAccessToken = errors.New("invalid auth access token")
var ErrInvalidRefreshToken = errors.New("invalid auth refresh token")
var ErrInvalidUserName = errors.New("invalid user name")
var ErrUserDoesNotExist = errors.New("user does not exist")
var ErrUserAlreadyExists = errors.New("user with such credentials already exist")
