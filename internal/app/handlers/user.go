package handlers

import (
	"auth/internal/app/errors"
	"auth/internal/app/interfaces"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/tokenmanager"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog/log"
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

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while request ReadAll")
		return
	}

	var u struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	err = json.Unmarshal(body, &u)

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while Unmarshal")
		return
	}

	user, err := c.store.User().GetByNameAndPassword(u.Login, u.Password)
	if returnErrorResponse(err != nil, w, r, http.StatusUnauthorized, nil, "Incorrect login or password") {
		log.Info().Err(err).Msg(fmt.Sprintf("Incorrect login or password at %s user", u.Login))
		return
	}

	accessTokenString, err := c.tm.GenerateAccessToken(user)
	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while GenerateAccessToken")
		return
	}

	refreshTokenString, err := c.tm.GenerateRefreshToken(user)

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while GenerateRefreshToken")
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

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while Marshal")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessTokenString,
		Expires:  tokenmanager.GetExpireTime(c.config.JWTAccessTokenLifeTime),
		SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  tokenmanager.GetExpireTime(c.config.JWTRefreshTokenLifeTime),
		SameSite: http.SameSiteNoneMode,
	})

	doRedirect(w, r)
	w.Write(successJSONResponse)

	log.Info().Msg(fmt.Sprintf("User %s logged in successfully", u.Login))
}

func (c *UserController) UserLogout(w http.ResponseWriter, r *http.Request) {
	profile := r.Context().Value("profile").(MiddlewareProfile)

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
	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while Marshal")
		return
	}

	c.cleanTokenCookies(&w)
	w.Header().Set("Content-Type", "application/json")
	doRedirect(w, r)
	w.Write(successJSONResponse)

	log.Info().Msg(fmt.Sprintf("User %s logged out successfully", profile.UserName))
}

func (c *UserController) UserRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := r.Cookie("refresh_token")
	if returnErrorResponse(err != nil, w, r, http.StatusUnauthorized, nil, "User not authorized") {
		log.Debug().Err(err).Msg("No refresh_token cookie")
		return
	}

	err = refreshToken.Valid()

	if returnErrorResponse(err != nil, w, r, http.StatusUnauthorized, nil, "User not authorized") {
		c.cleanTokenCookies(&w)
		log.Debug().Err(err).Msg("Invalid refresh_token")
		return
	}

	claims, err := c.tm.ParseRefreshToken(refreshToken.Value)

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Debug().Err(err).Msg("Unable to parse refresh_token")
		return
	}

	userInfo, err := c.store.User().GetByName(claims.Username)

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Debug().Err(err).Msg("Unable to get user by name")
		return
	}

	accessTokenString, refreshTokenString, err := c.generateTokens(userInfo)

	if returnErrorResponse(err != nil, w, r, http.StatusUnauthorized, err, "") {
		log.Error().Err(err).Msg("Error while generating tokens")
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

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while Marshal")
		return
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

	log.Debug().Msg("Tokens refreshed successfully")

}

func (c *UserController) UserInfo(w http.ResponseWriter, r *http.Request) {
	profile := r.Context().Value("profile").(MiddlewareProfile)
	userInfo, err := c.store.User().GetByName(profile.UserName)

	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Debug().Err(err).Msg("Unable to get user by name")
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
	if returnErrorResponse(err != nil, w, r, http.StatusInternalServerError, err, "") {
		log.Error().Err(err).Msg("Error while Marshal")
		return
	}

	w.Write(successJSONResponse)

	log.Debug().Msg("User info returned successfully")
}
