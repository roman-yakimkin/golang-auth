package mongo

import (
	"auth/internal/app/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id, omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"`
	Roles    []string           `bson:"roles"`
}

func (u *User) Export() *models.User {
	var user models.User
	user.ID = u.ID.Hex()
	user.Username = u.Username
	user.Password = u.Password
	user.Roles = append(user.Roles, u.Roles...)
	return &user
}

func (u *User) Import(user *models.User) error {
	var err error
	u.ID = primitive.ObjectID{}
	if user.ID != "" {
		u.ID, err = primitive.ObjectIDFromHex(user.ID)
		if err != nil {
			return err
		}
	}
	u.Username = user.Username
	u.Password = user.Password
	u.Roles = append(u.Roles, user.Roles...)
	return nil
}
