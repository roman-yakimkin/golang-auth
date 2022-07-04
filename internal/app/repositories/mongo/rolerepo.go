package mongo

import (
	"auth/internal/app/errors"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/dbclient"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type RoleRepo struct {
	config *configmanager.Config
	db     *dbclient.MongoDBClient
}

func NewRoleRepo(config *configmanager.Config, db *dbclient.MongoDBClient) *RoleRepo {
	var roles []models.Role
	for _, role := range config.Roles {
		roles = append(roles, models.Role{
			Name: role["name"].(string),
			Desc: role["desc"].(string),
		})
	}
	repo := RoleRepo{
		config: config,
		db:     db,
	}
	repo.initRoles(roles)
	return &repo
}

func (r *RoleRepo) initRoles(roles []models.Role) error {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return err
	}
	c := client.Database("auth_service").Collection("roles")
	for _, role := range roles {
		found := c.FindOne(ctx, bson.D{{"name", role.Name}})
		if found.Err() == mongo.ErrNoDocuments {
			_, err := c.InsertOne(ctx, bson.M{
				"name": role.Name,
				"desc": role.Desc,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *RoleRepo) GetByID(roleId string) (*models.Role, error) {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return nil, err
	}

	id, err := primitive.ObjectIDFromHex(roleId)
	if err != nil {
		return nil, err
	}

	c := client.Database("auth_service").Collection("roles")
	result := c.FindOne(ctx, bson.M{"_id": id})

	var mongoRole Role
	err = result.Decode(&mongoRole)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = errors.ErrRoleNotFound
		}
		return nil, err
	}

	role := mongoRole.Export()
	return role, nil
}

func (r *RoleRepo) GetByName(name string) (*models.Role, error) {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return nil, err
	}

	c := client.Database("auth_service").Collection("roles")
	result := c.FindOne(ctx, bson.M{"name": name})

	var mongoRole Role
	err = result.Decode(&mongoRole)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = errors.ErrRoleNotFound
		}
		return nil, err
	}

	role := mongoRole.Export()
	return role, nil
}
