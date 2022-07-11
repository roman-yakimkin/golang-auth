package mongo

import (
	"auth/internal/app/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Role struct {
	ID   primitive.ObjectID `bson:"_id, omitempty"`
	Name string             `bson:"name"`
	Desc string             `bson:"desc"`
}

func (r *Role) Export() *models.Role {
	var role models.Role
	role.ID = r.ID.Hex()
	role.Name = r.Name
	role.Desc = r.Desc
	return &role
}

func (r *Role) Import(role *models.Role) error {
	var err error
	r.ID = primitive.ObjectID{}
	if role.ID != "" {
		r.ID, err = primitive.ObjectIDFromHex(role.ID)
		if err != nil {
			return err
		}
	}
	r.Name = role.Name
	r.Desc = role.Desc
	return nil
}
