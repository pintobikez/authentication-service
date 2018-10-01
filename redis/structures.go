package redis

import (
	"github.com/garyburd/redigo/redis"
	cnf "github.com/pintobikez/authentication-service/config/structures"
	sec "github.com/pintobikez/authentication-service/secure/structures"
)

type ApiKey struct {
	Key string
}

type ClientI interface {
	Connect() (redis.Conn, error)
	CreateString(key string, value string) error
	CreateKey(key string, s *sec.TokenClaims) error
	DeleteKey(key string) error
	FindString(key string) (string, error)
	GetConfig() *cnf.RedisConfig
	Health() error
}
