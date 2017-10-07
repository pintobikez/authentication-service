package api

import (
	strut "github.com/pintobikez/authentication-service/api/structures"
	ldap "github.com/pintobikez/authentication-service/ldap"
	redis "github.com/pintobikez/authentication-service/redis"
	sec "github.com/pintobikez/authentication-service/secure/structures"
	"fmt"
	"github.com/labstack/echo"
	"log"
	"net/http"
	"strings"
)

type API struct {
	Secure sec.TokenManagerI
	Redis  redis.ClientI
	Ldap   ldap.ClientI
}

const (
	ErrorUserNotInGroups = "None of the User Groups are valid"
	StatusAvailable      = "Available"
	StatusUnavailable    = "Unavailable"
	IsEmpty              = "%s is empty"
	ErrorGroups          = "Error retrieving groups"
	TokenNotFound        = "Token not found for service: %s"
	ServiceNotRegistered = "Service %s is not registered, please contact us in order to register"
	TokenInvalid         = "The provided Token is invalid"
)

// Handler for Health Status
func (a *API) HealthStatus() echo.HandlerFunc {
	return func(c echo.Context) error {
		resp := &strut.HealthStatus{
			Ldap:     &strut.HealthStatusDetail{Status: StatusAvailable, Detail: ""},
			Redis:    &strut.HealthStatusDetail{Status: StatusAvailable, Detail: ""},
			Security: &strut.HealthStatusDetail{Status: StatusAvailable, Detail: ""},
		}

		if err := a.Ldap.Health(); err != nil {
			resp.Ldap.Status = StatusUnavailable
			resp.Ldap.Detail = err.Error()
		}
		if err := a.Redis.Health(); err != nil {
			resp.Redis.Status = StatusUnavailable
			resp.Redis.Detail = err.Error()
		}
		if err := a.Secure.Health(); err != nil {
			resp.Security.Status = StatusUnavailable
			resp.Security.Detail = err.Error()
		}

		return c.JSON(http.StatusOK, resp)
	}
}

// Handler to Validate the Token
func (a *API) Validate() echo.HandlerFunc {
	return func(c echo.Context) error {

		o := new(strut.TokenRequest)
		// if is an invalid json format
		if err := c.Bind(&o); err != nil {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, err.Error()})
		}

		if o.Username == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "username")})
		}
		if o.Service == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "service")})
		}
		if o.Token == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "token")})
		}

		//check if the API Key exist
		k := fmt.Sprintf(a.Redis.GetConfig().APIKey, o.Service)
		cipherKey, err := a.Redis.FindAPIKey(k)
		if err != nil || cipherKey == "" {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusForbidden, fmt.Sprintf(ServiceNotRegistered, o.Service)})
		}

		// FIND TOKEN IN REDIS
		key := fmt.Sprintf(a.Redis.GetConfig().TokenKey, o.Username, o.Service, o.Token)
		tkObj := new(sec.TokenClaims)
		if err := a.Redis.FindKey(key, tkObj); err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}

		if tkObj.Username == "" {
			return c.JSON(http.StatusNotFound, &ErrContent{http.StatusNotFound, fmt.Sprintf(TokenNotFound, o.Service)})
		}

		//If found:
		// 1 - VALIDATE TOKEN
		tkObj, err = a.Secure.ValidateToken(o.Token, cipherKey)
		if err != nil {
			return c.JSON(http.StatusNotFound, &ErrContent{http.StatusNotFound, err.Error()})
		}

		//Validate data consistency
		if tkObj.Username != o.Username || tkObj.Service != o.Service {
			return c.JSON(http.StatusNotFound, &ErrContent{http.StatusNotFound, fmt.Sprintf(TokenInvalid)})
		}

		//2 - Refresh the TTL in Redis
		err = a.Redis.CreateKey(key, tkObj)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}

		return c.NoContent(http.StatusOK)
	}
}

// Handler to Authenticate
func (a *API) Authenticate() echo.HandlerFunc {
	return func(c echo.Context) error {

		o := new(strut.AuthenticateRequest)
		// if is an invalid json format
		if err := c.Bind(&o); err != nil {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, err.Error()})
		}

		if o.Username == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "username")})
		}
		if o.Password == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "password")})
		}
		if o.Service == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "service")})
		}
		if len(o.Groups) == 0 {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, "groups")})
		}

		// FIND API TOKEN IN REDIS
		k := fmt.Sprintf(a.Redis.GetConfig().APIKey, o.Service)
		cipherKey, err := a.Redis.FindAPIKey(k)
		if err != nil || cipherKey == "" {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusForbidden, fmt.Sprintf(ServiceNotRegistered, o.Service)})
		}

		r := new(strut.AuthenticateResponse)

		// Error Connecting to LDAP server
		if err := a.Ldap.Connect(); err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}

		// Error performing user authentication
		if err := a.Ldap.Authenticate(o.Username, o.Password); err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}
		// Close LDAP connection
		defer a.Ldap.Close()

		groups, err := a.Ldap.GetGroupsOfUser(o.Username)
		// Error retrieving user groups
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, ErrorGroups})
		}

		// Validate if any of the user groups passed in the request exist the LDAP user groups
		gr := a.validateGroups(o.Groups, groups)

		// User doesn't belong to any group
		if len(gr) == 0 {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusForbidden, ErrorUserNotInGroups})
		}

		// 1 - GENERATE TOKEN
		tkObj := &sec.TokenClaims{Username: o.Username, Service: o.Service, Groups: gr}
		tokenString, err := a.Secure.CreateToken(tkObj, cipherKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}
		r.Token = tokenString

		// 2 - ADD TO REDIS
		key := fmt.Sprintf(a.Redis.GetConfig().TokenKey, o.Username, o.Service, tokenString)
		err = a.Redis.CreateKey(key, tkObj)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}

		return c.JSON(http.StatusOK, r)
	}
}

// Validate if any of the user groups passed in the request exist the LDAP user groups
// and return the groups where the user belongs to
func (a *API) validateGroups(validGroups []string, allGroups map[string]string) []string {

	var grr = make([]string, 0)
	for _, gr := range validGroups {
		log.Printf("%s \n", gr)
		gr := strings.ToUpper(gr)
		if _, exists := allGroups[gr]; exists {
			grr = append(grr, gr)
		}
	}

	return grr
}
