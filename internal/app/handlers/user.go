package handlers

import (
	"auth/internal/app/errors"
	"auth/internal/app/interfaces"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/tokenmanager"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type UserController struct {
	store  interfaces.Store
	tm     interfaces.TokenManager
	config *configmanager.Config
}

func NewUserController(store interfaces.Store, tm interfaces.TokenManager, cm *configmanager.Config) *UserController {
	return &UserController{
		store:  store,
		tm:     tm,
		config: cm,
	}
}

func (c *UserController) cleanTokenCookies(w *http.ResponseWriter) {
	http.SetCookie(*w, &http.Cookie{
		Name:   "access_token",
		Value:  "",
		MaxAge: 0,
	})
	http.SetCookie(*w, &http.Cookie{
		Name:   "refresh_token",
		Value:  "",
		MaxAge: 0,
	})
}

func (c *UserController) generateTokens(u *models.User) (string, string, error) {
	accessToken, _ := c.tm.GenerateAccessToken(u)
	if accessToken == "" {
		return "", "", errors.ErrInvalidAccessToken
	}
	refreshToken, _ := c.tm.GenerateRefreshToken(u)
	if refreshToken == "" {
		return "", "", errors.ErrInvalidRefreshToken
	}
	return accessToken, refreshToken, nil
}

func (c *UserController) UserLogin(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	var u map[string]string
	err = json.Unmarshal(body, &u)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
	}
	login, ok := u["login"]
	if !ok {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "The login field not found",
		})
		return
	}
	password, ok := u["password"]
	if !ok {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "The password field not found",
		})
		return
	}
	user, err := c.store.User().GetByNameAndPassword(login, password)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Incorrect login or password",
		})
		return
	}
	accessTokenString, err := c.tm.GenerateAccessToken(user)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	refreshTokenString, err := c.tm.GenerateRefreshToken(user)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	var successResponse = SuccessResponse{
		Code:    http.StatusOK,
		Message: "You have received a JWT token successfully",
		Response: SuccessfulLoginResponse{
			AccessToken:  accessTokenString,
			RefreshToken: refreshTokenString,
		},
	}
	successJSONResponse, err := json.Marshal(successResponse)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessTokenString,
		Expires: tokenmanager.GetExpireTime(c.config.JWTAccessTokenLifeTime),
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshTokenString,
		Expires: tokenmanager.GetExpireTime(c.config.JWTRefreshTokenLifeTime),
	})
	doRedirect(w, r)
	w.Write(successJSONResponse)
}

func (c *UserController) UserLogout(w http.ResponseWriter, r *http.Request) {
	refreshToken, _ := r.Cookie("refresh_token")
	refreshTokenStr := refreshToken.Value
	if refreshTokenStr != "" {
		c.store.ExpiredRT().MemorizeIfExpired(refreshTokenStr)
	}
	var successResponse = SuccessResponse{
		Code:    http.StatusOK,
		Message: "You have logged out",
	}
	successJSONResponse, err := json.Marshal(successResponse)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	doRedirect(w, r)
	w.Write(successJSONResponse)
}

func (c *UserController) UserRefreshToken(w http.ResponseWriter, r *http.Request) {
	var errorResponse = ErrorResponse{
		Code:    http.StatusInternalServerError,
		Message: "Internal Server Error",
	}
	refreshToken, err := r.Cookie("refresh_token")
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "User not authorized",
		})
		return
	}
	err = refreshToken.Valid()
	if err != nil {
		c.cleanTokenCookies(&w)
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "User not authorized",
		})
		return
	}
	claims, err := c.tm.ParseRefreshToken(refreshToken.Value)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	userInfo, err := c.store.User().GetByName(claims.Username)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	accessTokenString, refreshTokenString, err := c.generateTokens(userInfo)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: err.Error(),
		})
		return
	}
	var successResponse = SuccessResponse{
		Code:    http.StatusOK,
		Message: "JWT tokens have been updated successfully",
		Response: SuccessfulLoginResponse{
			AccessToken:  accessTokenString,
			RefreshToken: refreshTokenString,
		},
	}
	successJSONResponse, err := json.Marshal(successResponse)
	if err != nil {
		returnErrorResponse(w, r, errorResponse)
	}
	w.Header().Set("Content-Type", "application/json")
	http.SetCookie(w, &http.Cookie{
		Name:   "access_token",
		Value:  accessTokenString,
		MaxAge: 60,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "refresh_token",
		Value:  refreshTokenString,
		MaxAge: 3600,
	})
	w.Write(successJSONResponse)

}

func (c *UserController) UserInfo(w http.ResponseWriter, r *http.Request) {
	profile := r.Context().Value("profile").(MiddlewareProfile)
	userInfo, err := c.store.User().GetByName(profile.UserName)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var successResponse = SuccessResponse{
		Code:    http.StatusOK,
		Message: "User info",
		Response: UserInfoResponse{
			Username: userInfo.Username,
		},
	}
	successJSONResponse, err := json.Marshal(successResponse)
	if err != nil {
		returnErrorResponse(w, r, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
		return
	}
	w.Write(successJSONResponse)
}
