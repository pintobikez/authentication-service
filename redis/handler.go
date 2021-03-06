package redis

import (
	"encoding/json"
	"fmt"
	"github.com/garyburd/redigo/redis"
	cnf "github.com/pintobikez/authentication-service/config/structures"
	sec "github.com/pintobikez/authentication-service/secure/structures"
)

type Client struct {
	Config *cnf.RedisConfig
}

func New(c *cnf.RedisConfig) *Client {
	return &Client{Config: c}
}

// GetConfig retrieves the Redis Configuration
func (r *Client) GetConfig() *cnf.RedisConfig {
	return r.Config
}

// Connect to the Redis server
func (r *Client) Connect() (redis.Conn, error) {
	s, err := redis.Dial(r.Config.Mode, fmt.Sprintf("%s:%d", r.Config.Host, r.Config.Port))
	return s, err
}

// DeleteKey deletes the given Key from Redis
func (r *Client) DeleteKey(key string) error {

	c, err := r.Connect()
	// Error connecting to redis
	if err != nil {
		return err
	}
	defer c.Close()

	// delete KEY on Redis
	_, err = c.Do("DEL", key)
	if err != nil {
		return err
	}

	return nil
}

// CreateKey creates a key on Redis with the given TokenClaim
func (r *Client) CreateKey(key string, s *sec.TokenClaims) error {

	c, err := r.Connect()
	// Error connecting to redis
	if err != nil {
		return err
	}
	defer c.Close()

	// Format to JSON
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	// Save KEY to Redis
	_, err = c.Do("SET", key, b)
	if err != nil {
		return err
	}

	// Add TTL to KEY in Redis
	_, err = c.Do("EXPIRE", key, r.Config.TTL)
	if err != nil {
		return err
	}

	return nil
}

func (r *Client) FindString(key string) (string, error) {

	c, err := r.Connect()
	// Error connecting to redis
	if err != nil {
		return "", err
	}
	defer c.Close()

	reply, err := c.Do("GET", key)
	// Error retrieving key from redis
	if err != nil || reply == nil {
		return "", err
	}

	return string(reply.([]byte)), nil
}

// Health Endpoint of the Client
func (r *Client) CreateString(key string, value string) error {

	c, err := r.Connect()
	// Error connecting to redis
	if err != nil {
		return err
	}
	defer c.Close()

	// Save KEY to Redis
	_, err = c.Do("SET", key, value)
	if err != nil {
		return err
	}

	// Add TTL to KEY in Redis
	_, err = c.Do("EXPIRE", key, r.Config.APITTL)
	if err != nil {
		return err
	}

	return nil
}

// Health Endpoint of the Client
func (r *Client) Health() error {

	if r.Config == nil {
		return fmt.Errorf("Redis Config file not loaded")
	}

	conn, err := r.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}
