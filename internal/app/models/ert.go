package models

type ExpiredRefreshToken struct {
	Token   string `json:"token"`
	Expired int64  `json:"expired"`
}
