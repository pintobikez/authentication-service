package main

import (
	"context"
	middleware "github.com/dafiti/echo-middleware"
	inst "github.com/dafiti/go-instrument"
	"github.com/labstack/echo"
	mw "github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/color"
	"github.com/labstack/gommon/log"
	"github.com/pintobikez/authentication-service/api"
	uti "github.com/pintobikez/authentication-service/config"
	strut "github.com/pintobikez/authentication-service/config/structures"
	"github.com/pintobikez/authentication-service/ldap"
	lg "github.com/pintobikez/authentication-service/log"
	"github.com/pintobikez/authentication-service/redis"
	"github.com/pintobikez/authentication-service/secure"
	srv "github.com/pintobikez/authentication-service/server"
	"gopkg.in/urfave/cli.v1"
	"os"
	"os/signal"
	"time"
)

var (
	instrument inst.Instrument
	ldapCnf    *strut.LDAPConfig
	secCnf     *strut.SecurityConfig
	redisCnf   *strut.RedisConfig
)

func init() {
	instrument = new(inst.Dummy)
	ldapCnf = new(strut.LDAPConfig)
	secCnf = new(strut.SecurityConfig)
	redisCnf = new(strut.RedisConfig)
}

// Start Http Server
func Handler(c *cli.Context) error {

	// Echo instance
	e := &srv.Server{echo.New()}
	e.HTTPErrorHandler = api.Error
	e.Logger.SetLevel(log.INFO)
	e.Logger.SetOutput(lg.File(c.String("log-folder") + "/app.log"))

	// Middlewares
	e.Use(middleware.LoggerWithOutput(lg.File(c.String("log-folder") + "/access.log")))
	e.Use(mw.Recover())
	e.Use(mw.Secure())
	e.Use(mw.RequestID())
	e.Pre(mw.RemoveTrailingSlash())

	if c.String("newrelic-appname") != "" && c.String("newrelic-license-key") != "" {
		e.Use(middleware.NewRelic(
			c.String("newrelic-appname"),
			c.String("newrelic-license-key"),
		))

		instrument = new(inst.NewRelic)
	}

	//loads ldap config if not to override LDAP
	ldapC := &ldap.Client{}

	if !c.Bool("ldap-override") {
		err := uti.LoadConfigFile(c.String("ldap-file"), ldapCnf)
		if err != nil {
			e.Logger.Fatal(err)
		}
		ldapC = ldap.New(ldapCnf)
	} else {
		ldapC.IsMock = true
	}

	//loads security config
	err := uti.LoadConfigFile(c.String("security-file"), secCnf)
	if err != nil {
		e.Logger.Fatal(err)
	}
	securC := &secure.TokenManager{secCnf}

	//loads redis config
	err = uti.LoadConfigFile(c.String("redis-file"), redisCnf)
	if err != nil {
		e.Logger.Fatal(err)
	}
	redisC := redis.New(redisCnf)

	a := &api.API{Ldap: ldapC, Redis: redisC, Secure: securC}

	// Routes => api
	e.POST("/authenticate", a.Authenticate(), mw.CORSWithConfig(
		mw.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{echo.GET, echo.OPTIONS, echo.HEAD},
		},
	))
	e.POST("/validate", a.Validate(), mw.CORSWithConfig(
		mw.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{echo.POST, echo.OPTIONS, echo.HEAD},
		},
	))
	e.GET("/health", a.HealthStatus(), mw.CORSWithConfig(
		mw.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{echo.GET, echo.OPTIONS, echo.HEAD},
		},
	))

	if c.String("revision-file") != "" {
		e.File("/rev.txt", c.String("revision-file"))
	}

	if swagger := c.String("swagger-file"); swagger != "" {
		g := e.Group("/docs")
		g.Use(mw.CORSWithConfig(
			mw.CORSConfig{
				AllowOrigins: []string{"http://petstore.swagger.io"},
				AllowMethods: []string{echo.GET, echo.HEAD},
			},
		))

		g.GET("", func(c echo.Context) error {
			return c.File(swagger)
		})
	}

	// Start server
	colorer := color.New()
	colorer.Printf("⇛ %s service - %s\n", appName, color.Green(version))
	//Print available routes
	colorer.Printf("⇛ Available Routes:\n")
	for _, rou := range e.Routes() {
		colorer.Printf("⇛ URI: [%s] %s\n", color.Green(rou.Method), color.Green(rou.Path))
	}

	go func() {
		if err := start(e, c); err != nil {
			colorer.Printf(color.Red("⇛ shutting down the server\n"))
		}
	}()

	// Graceful Shutdown
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}

	return nil
}

// Start http or https server when certificates are defined
func start(e *srv.Server, c *cli.Context) error {

	if c.String("ssl-cert") != "" && c.String("ssl-key") != "" {
		return e.StartTLS(
			c.String("listen"),
			c.String("ssl-cert"),
			c.String("ssl-key"),
		)
	}

	return e.Start(c.String("listen"))
}
