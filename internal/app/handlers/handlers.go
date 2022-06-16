package handlers

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Code    int    `json: "code"`
	Message string `json:"message"`
}

type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

type SuccessfulLoginResponse struct {
	AccessToken  string
	RefreshToken string
}

type UserInfoResponse struct {
	Username string `json:"username"`
}

func returnErrorResponse(w http.ResponseWriter, r *http.Request, errorMsg ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMsg.Code, Message: errorMsg.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorMsg.Code)
	w.Write(jsonResponse)
}
