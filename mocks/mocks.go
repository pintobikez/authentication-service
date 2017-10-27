package mocks

import (
	"fmt"
	rlib "github.com/garyburd/redigo/redis"
	cnf "github.com/pintobikez/authentication-service/config/structures"
	. "github.com/pintobikez/authentication-service/secure/structures"
)

// MOCK STRUCTURES DEFINITION
type (
	ClientTokenManagerTest struct {
		Iserror bool
	}
	ClientLdapTest struct {
		Iserror bool
	}
	ClientRedisTest struct {
		Iserror       bool
		IserrorUser   bool
		IserrorCreate bool
		IserrorAPI    bool
	}
	ConnMock struct {
	}
)

// MOCK github.com/garyburd/redigo/redis conn structure - START
func (c *ConnMock) Close() error {
	return nil
}
func (c *ConnMock) Err() error {
	return nil
}
func (c *ConnMock) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	return nil, nil
}
func (c *ConnMock) Send(commandName string, args ...interface{}) error {
	return nil
}
func (c *ConnMock) Flush() error {
	return nil
}
func (c *ConnMock) Receive() (reply interface{}, err error) {
	return nil, nil
}

// MOCK github.com/garyburd/redigo/redis conn structure - END

// MOCK REDIS INTERFACE - START
func (c *ClientRedisTest) Connect() (rlib.Conn, error) {
	return new(ConnMock), nil
}
func (c *ClientRedisTest) GetConfig() *cnf.RedisConfig {
	return &cnf.RedisConfig{APIKey: "serviceapikey@@%s", TokenKey: "token@@%s@@%s@@%s"}
}
func (c *ClientRedisTest) FindString(key string) (string, error) {
	if c.IserrorAPI {
		return "", nil
	}
	return "A12345", nil
}
func (c *ClientRedisTest) CreateString(key string, value string) error {
	return nil
}
func (c *ClientRedisTest) FindKey(key string, s *TokenClaims) error {
	if c.Iserror {
		return fmt.Errorf("error in finding key")
	}
	if c.IserrorUser {
		s.Username = ""
		return nil
	}

	s.Username = "T"
	s.Service = "T"

	return nil
}
func (c *ClientRedisTest) CreateKey(key string, s *TokenClaims) error {
	if c.IserrorCreate == true {
		return fmt.Errorf("error in creating key")
	}
	return nil
}
func (c *ClientRedisTest) Health() error {
	if c.Iserror {
		return fmt.Errorf("Error Redis Health")
	}
	return nil
}

// MOCK REDIS INTERFACE - END

// MOCK SECURE INTERFACE - START
func (c *ClientTokenManagerTest) CreateToken(tk *TokenClaims, cipher string) (string, error) {
	if c.Iserror {
		return "", fmt.Errorf("Error creating token")
	}
	return "cryptoText", nil
}
func (c *ClientTokenManagerTest) ValidateToken(tokenString string, cipher string) (*TokenClaims, error) {
	if c.Iserror {
		return nil, fmt.Errorf("error in token")
	}
	return &TokenClaims{Username: "V", Service: "V"}, nil
}
func (c *ClientTokenManagerTest) Health() error {
	if c.Iserror {
		return fmt.Errorf("Error TokenManager Health")
	}
	return nil
}

// MOCK SECURE INTERFACE - END

// MOCK LDAP INTERFACE - START
func (c *ClientLdapTest) Connect() error {
	if c.Iserror {
		return fmt.Errorf("Error decrypting")
	}
	return nil
}
func (c *ClientLdapTest) Close() {}

func (c *ClientLdapTest) Authenticate(username, password string) error {
	if username == "B" {
		return fmt.Errorf("Error Auth")
	}
	return nil
}
func (c *ClientLdapTest) GetGroupsOfUser(username string) (map[string]string, error) {

	if username == "C" {
		return nil, fmt.Errorf("Error Auth")
	}
	gr := make(map[string]string)
	if username == "E" {
		gr["B"] = "B"
	} else {
		gr["A"] = "A"
	}

	return gr, nil
}
func (c *ClientLdapTest) Health() error {
	if c.Iserror {
		return fmt.Errorf("Error LDAP Health")
	}
	return nil
}

// MOCK LDAP INTERFACE - END
