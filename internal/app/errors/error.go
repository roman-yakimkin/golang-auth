package errors

import "errors"

var ErrInvalidAccessToken = errors.New("invalid auth access token")
var ErrInvalidRefreshToken = errors.New("invalid auth refresh token")

var ErrInvalidUserName = errors.New("invalid user name")
var ErrUserNotFound = errors.New("user not found")
var ErrUserAlreadyExists = errors.New("user with such credentials already exist")

var ErrRoleNotFound = errors.New("role not found")
