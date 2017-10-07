package redis

import (
	cnf "github.com/pintobikez/authentication-service/config/structures"
	sec "github.com/pintobikez/authentication-service/secure/structures"
	"github.com/garyburd/redigo/redis"
)

type ApiKey struct {
	Key string
}

type ClientI interface {
	Connect() (redis.Conn, error)
	CreateAPIKey(key string, value string) error
	CreateKey(key string, s *sec.TokenClaims) error
	FindKey(key string, s *sec.TokenClaims) error
	FindAPIKey(key string) (string, error)
	GetConfig() *cnf.RedisConfig
	Health() error
}
