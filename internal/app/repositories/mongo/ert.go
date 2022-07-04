package mongo

import (
	"auth/internal/app/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ExpiredRefreshToken struct {
	ID      primitive.ObjectID `bson:"_id, omitempty"`
	Token   string             `bson:"token"`
	Expired int64              `bson:"expired"`
}

func (t *ExpiredRefreshToken) Export() *models.ExpiredRefreshToken {
	var token models.ExpiredRefreshToken
	token.ID = t.ID.Hex()
	token.Token = t.Token
	token.Expired = t.Expired
	return &token
}

func (t *ExpiredRefreshToken) Import(token *models.ExpiredRefreshToken) error {
	var err error
	t.ID = primitive.ObjectID{}
	if token.ID != "" {
		t.ID, err = primitive.ObjectIDFromHex(token.ID)
		if err != nil {
			return err
		}
	}
	t.Token = token.Token
	t.Expired = token.Expired
	return nil
}
