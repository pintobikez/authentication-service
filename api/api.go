package api

import (
	"fmt"
	"github.com/labstack/echo"
	strut "github.com/pintobikez/authentication-service/api/structures"
	ldap "github.com/pintobikez/authentication-service/ldap"
	redis "github.com/pintobikez/authentication-service/redis"
	sec "github.com/pintobikez/authentication-service/secure/structures"
	"net/http"
	"strings"
)

type API struct {
	Secure sec.TokenManagerI
	Redis  redis.ClientI
	Ldap   ldap.ClientI
}

const (
	HeaderService        = "AuthorizationRequestBy"
	ErrorUserNotInGroups = "None of the User Groups are valid"
	StatusAvailable      = "Available"
	StatusUnavailable    = "Unavailable"
	IsEmpty              = "%s is empty"
	ErrorGroups          = "Error retrieving groups"
	TokenNotFound        = "Token not found for service: %s"
	ServiceNotRegistered = "Service %s is not registered, please contact admin team in order to register"
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

		token := c.Request().Header.Get(echo.HeaderAuthorization)
		if token == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, echo.HeaderAuthorization)})
		}
		service := c.Request().Header.Get(HeaderService)
		if service == "" {
			return c.JSON(http.StatusBadRequest, &ErrContent{http.StatusBadRequest, fmt.Sprintf(IsEmpty, HeaderService)})
		}

		//check if the API Key exist
		k := fmt.Sprintf(a.Redis.GetConfig().APIKey, service)
		cipherKey, err := a.Redis.FindString(k)
		if err != nil || cipherKey == "" {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusForbidden, fmt.Sprintf(ServiceNotRegistered, service)})
		}

		//If found:
		// 1 - VALIDATE TOKEN
		tkObj, err := a.Secure.ValidateToken(token, cipherKey)
		if err != nil {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusNotFound, err.Error()})
		}

		//Validate data consistency
		if tkObj.Service != service {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusNotFound, fmt.Sprintf(TokenInvalid)})
		}

		//2 - Refresh the TTL in Redis
		key := fmt.Sprintf(a.Redis.GetConfig().TokenKey, tkObj.Username, service, token)
		err = a.Redis.CreateKey(key, tkObj)
		if err != nil {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusNotFound, err.Error()})
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
		cipherKey, err := a.Redis.FindString(k)
		if err != nil || cipherKey == "" {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusForbidden, fmt.Sprintf(ServiceNotRegistered, o.Service)})
		}

		r := new(strut.AuthenticateResponse)

		// Error Connecting to LDAP server
		if err := a.Ldap.Connect(); err != nil {
			return c.JSON(http.StatusInternalServerError, &ErrContent{http.StatusInternalServerError, err.Error()})
		}

		// Error performing user authentication
		name, err := a.Ldap.Authenticate(o.Username, o.Password)
		if err != nil {
			return c.JSON(http.StatusForbidden, &ErrContent{http.StatusInternalServerError, err.Error()})
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
		tkObj := &sec.TokenClaims{Username: o.Username, Service: o.Service, Groups: gr, Name: name}
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
		gr := strings.ToUpper(gr)
		if _, exists := allGroups[gr]; exists {
			grr = append(grr, gr)
		}
	}

	return grr
}
