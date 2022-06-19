package handlers

import (
	"auth/internal/app/services/tokenmanager"
	"context"
	"golang.org/x/exp/slices"
	"net/http"
)

var noLoggingMiddlewarePaths = []string{
	"/login",
}

type MiddlewareProfile struct {
	UserName string
}

type Middleware struct {
	tm tokenmanager.TokenManager
}

func NewMiddleware(tm tokenmanager.TokenManager) *Middleware {
	return &Middleware{
		tm: tm,
	}
}

func (mw *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(noLoggingMiddlewarePaths, r.URL.Path) {
			accessCookie, err := r.Cookie("access_token")
			if err != nil {
				returnErrorResponse(w, r, ErrorResponse{
					Code:    http.StatusUnauthorized,
					Message: err.Error(),
				})
				return
			}
			claims, err := mw.tm.ParseAccessToken(accessCookie.Value)
			if err != nil {
				returnErrorResponse(w, r, ErrorResponse{
					Code:    http.StatusUnauthorized,
					Message: err.Error(),
				})
				return
			}
			if claims.Username == "" {
				returnErrorResponse(w, r, ErrorResponse{
					Code:    http.StatusUnauthorized,
					Message: tokenmanager.ErrInvalidUserName.Error(),
				})
				return
			}
			ctx := r.Context()
			r = r.WithContext(context.WithValue(ctx, "profile", MiddlewareProfile{
				UserName: claims.Username,
			}))
		}
		next.ServeHTTP(w, r)
	})
}
