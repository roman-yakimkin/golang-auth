package handlers

import (
	"auth/internal/app/errors"
	"auth/internal/app/interfaces"
	"context"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
)

var noLoggingMiddlewarePaths = []string{
	"^/login(?)?(.)*$",
}

type MiddlewareProfile struct {
	UserName string
}

type Middleware struct {
	tm interfaces.TokenManager
}

func NewMiddleware(tm interfaces.TokenManager) *Middleware {
	return &Middleware{
		tm: tm,
	}
}

func (mw *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, path := range noLoggingMiddlewarePaths {
			ok, err := regexp.Match(path, []byte(r.URL.Path))

			if err != nil {
				log.Print(err)
			}

			if !ok {
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
						Message: errors.ErrInvalidUserName.Error(),
					})
					return
				}

				ctx := r.Context()
				r = r.WithContext(context.WithValue(ctx, "profile", MiddlewareProfile{
					UserName: claims.Username,
				}))
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}
