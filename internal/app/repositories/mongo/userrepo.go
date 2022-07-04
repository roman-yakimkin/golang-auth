package mongo

import (
	"auth/internal/app/errors"
	"auth/internal/app/interfaces"
	"auth/internal/app/models"
	"auth/internal/app/services/configmanager"
	"auth/internal/app/services/dbclient"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepo struct {
	pm     interfaces.PasswordManager
	config *configmanager.Config
	db     *dbclient.MongoDBClient
}

func NewUserRepo(pm interfaces.PasswordManager, config *configmanager.Config, db *dbclient.MongoDBClient) *UserRepo {
	var users []models.User

	for _, user := range config.Users {
		var roles []string
		for _, role := range user["roles"].([]interface{}) {
			roles = append(roles, role.(string))
		}
		users = append(users, models.User{
			Username: user["username"].(string),
			Password: user["password"].(string),
			Roles:    roles,
		})
	}
	repo := UserRepo{
		pm:     pm,
		config: config,
		db:     db,
	}
	repo.initUsers(users)
	return &repo
}

func (r *UserRepo) initUsers(users []models.User) error {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return err
	}
	c := client.Database("auth_service").Collection("users")
	for _, user := range users {
		found := c.FindOne(ctx, bson.D{{"username", user.Username}})
		if found.Err() == mongo.ErrNoDocuments {
			_, err := c.InsertOne(ctx, bson.M{
				"username": user.Username,
				"password": user.Password,
				"roles":    user.Roles,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *UserRepo) GetByID(uid string) (*models.User, error) {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return nil, err
	}

	id, err := primitive.ObjectIDFromHex(uid)
	if err != nil {
		return nil, err
	}

	c := client.Database("auth_service").Collection("users")
	result := c.FindOne(ctx, bson.M{"_id": id})

	var mongoUser User
	err = result.Decode(&mongoUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = errors.ErrUserNotFound
		}
		return nil, err
	}

	user := mongoUser.Export()
	return user, nil
}

func (r *UserRepo) GetByName(name string) (*models.User, error) {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return nil, err
	}

	c := client.Database("auth_service").Collection("users")
	result := c.FindOne(ctx, bson.M{"username": name})

	var mongoUser User
	err = result.Decode(&mongoUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = errors.ErrUserNotFound
		}
		return nil, err
	}

	user := mongoUser.Export()
	return user, nil
}

func (r *UserRepo) GetByNameAndPassword(name string, password string) (*models.User, error) {
	user, err := r.GetByName(name)
	if err != nil {
		return nil, err
	}
	if !r.pm.ComparePasswords(user.Password, password) {
		return nil, errors.ErrUserNotFound
	}
	return user, nil
}
