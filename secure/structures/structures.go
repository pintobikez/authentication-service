package structures

import "github.com/dgrijalva/jwt-go"

type TokenManagerI interface {
	CreateToken(tk *TokenClaims, cipher string) (string, error)
	ValidateToken(token string, cipher string) (*TokenClaims, error)
	Health() error
}

type TokenClaims struct {
	Username string   `json:"username"`
	Service  string   `json:"service"`
	Groups   []string `json:"groups"`
	jwt.StandardClaims
}
