package models

type ExpiredRefreshToken struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Expired int64  `json:"expired"`
}
