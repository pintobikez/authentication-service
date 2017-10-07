package api

import (
	apis "github.com/pintobikez/authentication-service/api/structures"
	strut "github.com/pintobikez/authentication-service/config/structures"
	"github.com/pintobikez/authentication-service/ldap"
	"github.com/pintobikez/authentication-service/mocks"
	"encoding/json"
	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

/* Test for ValidateGroups method */
func TestValidateGroups(t *testing.T) {

	map1 := make(map[string]string)
	map1["TESTE"] = "TESTE"

	map2 := make(map[string]string)
	map2["TESTE"] = "TESTE"
	map2["TESTE2"] = "TESTE2"

	a := new(API)
	v := a.validateGroups([]string{"teste"}, map1)
	assert.Equal(t, v, []string{"TESTE"})

	v = a.validateGroups([]string{"teste"}, map2)
	assert.Equal(t, v, []string{"TESTE"})

	v = a.validateGroups([]string{"teste2"}, map1)
	assert.Equal(t, v, []string{})
}

/*
Data Provider for Validate method
*/
type validateProvider struct {
	method string
	value  string
	erro   string
	json   string
	result int
}

var testValidateProvider = []validateProvider{
	{echo.POST, "/validate", "", "", http.StatusBadRequest},                                                        // invalid json
	{echo.POST, "/validate", "", `{"token":"A","service":"A"}`, http.StatusBadRequest},                             // no username in json
	{echo.POST, "/validate", "", `{"username":"A","service":"A"}`, http.StatusBadRequest},                          // no token in json
	{echo.POST, "/validate", "", `{"username":"A","token":"A"}`, http.StatusBadRequest},                            // no service in json
	{echo.POST, "/validate", "rdis", `{"username":"A","token":"C","service":"A"}`, http.StatusInternalServerError}, // redis key not found
	{echo.POST, "/validate", "token", `{"username":"T","token":"T","service":"T"}`, http.StatusNotFound},           // validate token error
	{echo.POST, "/validate", "user", `{"username":"T","token":"T","service":"T"}`, http.StatusNotFound},            // validate consistency error
	{echo.POST, "/validate", "", `{"username":"T","token":"T","service":"T"}`, http.StatusNotFound},                // validate token error
	{echo.POST, "/validate", "keyc", `{"username":"V","token":"V","service":"V"}`, http.StatusInternalServerError}, // error creating key in redis
	{echo.POST, "/validate", "apit", `{"username":"V","token":"T","service":"V"}`, http.StatusForbidden},           // API Key not found
	{echo.POST, "/validate", "", `{"username":"V","token":"T","service":"V"}`, http.StatusOK},                      // OK
}

/*
Tests for Validate method
*/
func TestValidate(t *testing.T) {

	l := ldap.New(&strut.LDAPConfig{})

	for _, pair := range testValidateProvider {
		// API SETUP
		r := new(mocks.ClientRedisTest)
		s := new(mocks.ClientTokenManagerTest)
		a := API{Secure: s, Redis: r, Ldap: l}

		if pair.erro == "user" {
			r.IserrorUser = true
		}
		if pair.erro == "keyc" {
			r.IserrorCreate = true
		}
		if pair.erro == "rdis" {
			r.Iserror = true
		}
		if pair.erro == "apit" {
			r.IserrorAPI = true
		}
		if pair.erro == "token" {
			s.Iserror = true
		}

		// Setup
		e := echo.New()
		e.POST("/validate", a.Validate())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(pair.method, pair.value, strings.NewReader(pair.json))
		req.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(rec, req)
		// Assertions
		assert.Equal(t, pair.result, rec.Code)
	}
}

/*
Data Provider for Authentication method
*/
type authenticationProvider struct {
	method string
	value  string
	erro   string
	json   string
	result int
}

var testAuthenticationProvider = []authenticationProvider{
	{echo.POST, "/authenticate", "", "", http.StatusBadRequest},                                                                           // invalid json
	{echo.POST, "/authenticate", "", `{"password":"A","service":"A"}`, http.StatusBadRequest},                                             // no username in json
	{echo.POST, "/authenticate", "", `{"username":"A","service":"A"}`, http.StatusBadRequest},                                             // no password in json
	{echo.POST, "/authenticate", "", `{"username":"A","password":"A"}`, http.StatusBadRequest},                                            // no service in json
	{echo.POST, "/authenticate", "", `{"username":"A","password":"A","service":"A"}`, http.StatusBadRequest},                              // no group in json
	{echo.POST, "/authenticate", "ldap", `{"username":"A","password":"A","service":"A", "groups":["A"]}`, http.StatusInternalServerError}, // error in Ldap Connect
	{echo.POST, "/authenticate", "sec", `{"username":"A","password":"A","service":"A", "groups":["A"]}`, http.StatusInternalServerError},  // error in Decrypt
	{echo.POST, "/authenticate", "", `{"username":"B","password":"A","service":"A", "groups":["A"]}`, http.StatusInternalServerError},     // error in Auth LDAP
	{echo.POST, "/authenticate", "", `{"username":"C","password":"A","service":"A", "groups":["A"]}`, http.StatusInternalServerError},     // error in Groups LDAP
	{echo.POST, "/authenticate", "rdis", `{"username":"D","password":"A","service":"A", "groups":["A"]}`, http.StatusInternalServerError}, // error creating key in redis
	{echo.POST, "/authenticate", "apit", `{"username":"A","password":"A","service":"D", "groups":["A"]}`, http.StatusForbidden},           // API Key not found
	{echo.POST, "/authenticate", "", `{"username":"E","password":"A","service":"A", "groups":["A"]}`, http.StatusForbidden},               // OK but group not found
	{echo.POST, "/authenticate", "", `{"username":"A","password":"A","service":"A", "groups":["A"]}`, http.StatusOK},                      // OK
}

/*
Tests for Authentication method
*/
func TestAuthenticate(t *testing.T) {

	for _, pair := range testAuthenticationProvider {

		// API SETUP
		l := new(mocks.ClientLdapTest)
		r := new(mocks.ClientRedisTest)
		s := new(mocks.ClientTokenManagerTest)
		if pair.erro == "ldap" {
			l.Iserror = true
		}
		if pair.erro == "sec" {
			s.Iserror = true
		}
		if pair.erro == "rdis" {
			r.IserrorCreate = true
		}
		if pair.erro == "apit" {
			r.IserrorAPI = true
		}
		a := API{Secure: s, Redis: r, Ldap: l}

		// Setup
		e := echo.New()
		e.POST("/authenticate", a.Authenticate())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(pair.method, pair.value, strings.NewReader(pair.json))
		req.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(rec, req)
		// Assertions
		assert.Equal(t, pair.result, rec.Code)
	}
}

/*
Data Provider for HealthStatus method
*/
type healthProvider struct {
	method string
	value  string
	erro   string
}

var testHealthProvider = []healthProvider{
	{echo.GET, "/health", ""},      // OK
	{echo.GET, "/health", "redis"}, // error in Redis
	{echo.GET, "/health", "ldap"},  // error in Ldap
	{echo.GET, "/health", "sec"},   // error in Security
}

/*
Tests for Health method
*/
func TestHealth(t *testing.T) {

	for _, pair := range testHealthProvider {
		// API SETUP
		l := new(mocks.ClientLdapTest)
		r := new(mocks.ClientRedisTest)
		s := new(mocks.ClientTokenManagerTest)

		switch pair.erro {
		case "ldap":
			l.Iserror = true
			break
		case "redis":
			r.Iserror = true
			break
		case "sec":
			s.Iserror = true
			break
		}

		a := API{Secure: s, Redis: r, Ldap: l}

		// Setup
		e := echo.New()
		e.GET("/health", a.HealthStatus())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(pair.method, pair.value, strings.NewReader(""))

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		val := new(apis.HealthStatus)
		_ = json.Unmarshal([]byte(rec.Body.String()), val)

		// Assertions
		switch pair.erro {
		case "ldap":
			assert.Equal(t, val.Ldap.Status, StatusUnavailable)
			break
		case "redis":
			assert.Equal(t, val.Redis.Status, StatusUnavailable)
			break
		case "sec":
			assert.Equal(t, val.Security.Status, StatusUnavailable)
			break
		}
	}
}
