package secure

import (
	cnf "github.com/pintobikez/authentication-service/config/structures"
	strut "github.com/pintobikez/authentication-service/secure/structures"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var (
	ErrorSigningMethod = errors.New("Unexpected siging method")
	ErrorTokenObject   = errors.New("Invalid token content")
	ErrorConfigFile    = errors.New("Security Config file not loaded")
	ErrorConfigValues  = errors.New("Security Config contains errors")
)

type TokenManager struct {
	Config *cnf.SecurityConfig
}

// Generates a JWT token
func (s *TokenManager) CreateToken(tk *strut.TokenClaims, cipher string) (string, error) {

	// Add the time of expire time for the token
	tk.ExpiresAt = time.Now().Add(time.Duration(s.Config.TTL) * time.Minute).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tk)
	tokenString, err := token.SignedString([]byte(cipher))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *TokenManager) ValidateToken(tokenString string, cipher string) (*strut.TokenClaims, error) {
	// Return a Token using the tokenString
	token, err := jwt.ParseWithClaims(tokenString, &strut.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure token's signature wasn't changed
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrorSigningMethod
		}
		return []byte(cipher), nil
	})
	if err != nil {
		return nil, err
	}

	// Grab the tokens claims and pass it into the original request
	if claims, ok := token.Claims.(*strut.TokenClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrorTokenObject
}

// Health Endpoint of the Client
func (s *TokenManager) Health() error {
	if s.Config == nil {
		return ErrorConfigFile
	}
	if s.Config.TTL <= 0 || s.Config.CipherKey == "" {
		return ErrorConfigValues
	}
	return nil
}
