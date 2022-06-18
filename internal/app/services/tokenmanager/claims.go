package tokenmanager

import "github.com/dgrijalva/jwt-go"

type AccessClaims struct {
	jwt.StandardClaims
	Username string
	Roles    []string
}

type RefreshClaims struct {
	jwt.StandardClaims
	Username string
}
