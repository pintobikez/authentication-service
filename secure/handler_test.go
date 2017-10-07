package secure

import (
	strut "github.com/pintobikez/authentication-service/config/structures"
	. "github.com/pintobikez/authentication-service/secure/structures"
	// "fmt"
	"github.com/stretchr/testify/assert"
	// "log"
	"testing"
)

/*
Provider struct for CreateToken method
*/
type providerCreateToken struct {
	cipher string
	ttl    int
	iserro bool
}

var testProviderCreateToken = []providerCreateToken{
	{"12312321", 0, false}, // ok
	{"", 10, false},        // ok
	{"!", 10, false},       // ok
}

/* Test for CreateToken method */
func TestCreateToken(t *testing.T) {

	for _, pair := range testProviderCreateToken {

		s := &TokenManager{&strut.SecurityConfig{CipherKey: pair.cipher, TTL: pair.ttl}}
		tk := new(TokenClaims)
		_, err := s.CreateToken(tk, pair.cipher)
		// Assertions
		assert.Equal(t, pair.iserro, (err != nil))
	}
}

/*
Provider struct for ValidateToken method
*/
type providerValidateToken struct {
	cipher    string
	ttl       int
	changekey bool
	iserro    bool
	message   string
}

var testProviderValidateToken = []providerValidateToken{
	{"", 10, false, false, ""},                   // OK
	{"", 10, true, true, "signature is invalid"}, // OK
}

/* Test for ValidateToken method */
func TestValidateToken(t *testing.T) {

	for _, pair := range testProviderValidateToken {

		s := &TokenManager{&strut.SecurityConfig{CipherKey: pair.cipher, TTL: pair.ttl}}
		tk := new(TokenClaims)
		tk.Username = "teste"
		res, _ := s.CreateToken(tk, pair.cipher)

		if pair.changekey {
			res += "1"
		}
		val, err := s.ValidateToken(res, pair.cipher)
		// Assertions
		assert.Equal(t, pair.iserro, (err != nil))
		if err != nil {
			assert.Equal(t, err.Error(), pair.message)
		} else {
			assert.Equal(t, val.Username, "teste")
		}
	}
}

/*
Provider struct for Health method
*/
type tokenHealthProvider struct {
	configok bool
	ttl      int
	cipher   string
	result   error
}

var testTokenHealthProvider = []tokenHealthProvider{
	{false, 0, "123123123123123123", ErrorConfigFile},  // no config file
	{true, 0, "123123123123123123", ErrorConfigValues}, // invalid ttl value
	{true, 10, "", ErrorConfigValues},                  // invalid cipher value
	{true, 10, "123123123123123123", nil},              // OK
}

/* Test for DecryptString method */
func TestHealth(t *testing.T) {

	for _, pair := range testTokenHealthProvider {

		var conf *strut.SecurityConfig

		if pair.configok {
			conf = &strut.SecurityConfig{CipherKey: pair.cipher, TTL: pair.ttl}
		}
		s := &TokenManager{conf}
		err := s.Health()

		// Assertions
		if err != nil {
			assert.Equal(t, pair.result.Error(), err.Error())
		} else {
			assert.Equal(t, pair.result, err)
		}
	}
}
