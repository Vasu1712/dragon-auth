package storage

import (
	"crypto/tls"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient(password, host string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     host + ":6379",
		Password: password,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	})
}
