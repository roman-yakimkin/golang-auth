package mongo

import (
	"auth/internal/app/interfaces"
	"auth/internal/app/services/dbclient"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type ExpiredRefreshTokenRepo struct {
	tm interfaces.TokenManager
	db *dbclient.MongoDBClient
}

func NewExpiredRefreshTokenRepo(tm interfaces.TokenManager, db *dbclient.MongoDBClient) *ExpiredRefreshTokenRepo {
	return &ExpiredRefreshTokenRepo{
		tm: tm,
		db: db,
	}
}

func (r *ExpiredRefreshTokenRepo) MemorizeIfExpired(token string) error {
	claims, err := r.tm.ParseRefreshToken(token)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return err
	}

	c := client.Database("auth_service").Collection("expired_tokens")
	_, err = c.InsertOne(ctx, bson.M{
		"token":   token,
		"expired": claims.ExpiresAt,
	})

	return err
}

func (r *ExpiredRefreshTokenRepo) IsExpired(token string) (bool, error) {
	claims, err := r.tm.ParseRefreshToken(token)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return false, err
	}

	c := client.Database("auth_service").Collection("expired_tokens")

	var mongoErt ExpiredRefreshToken
	err = c.FindOne(ctx, bson.M{"token": token}).Decode(&mongoErt)

	return err != mongo.ErrNoDocuments || claims.ExpiresAt <= time.Now().Unix(), nil
}

func (r *ExpiredRefreshTokenRepo) Clean() error {
	ctx := context.Background()
	client, err := r.db.Connect(ctx)
	defer r.db.Disconnect(ctx)
	if err != nil {
		return err
	}

	c := client.Database("auth_service").Collection("expired_tokens")
	filter := bson.D{
		{"expired", bson.D{{"$lte", time.Now().Unix()}}},
	}
	_, err = c.DeleteMany(ctx, filter)

	return err
}
