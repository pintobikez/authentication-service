package main

import (
	uti "github.com/pintobikez/authentication-service/config"
	strut "github.com/pintobikez/authentication-service/config/structures"
	"github.com/pintobikez/authentication-service/redis"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/gommon/color"
	"gopkg.in/urfave/cli.v1"
)

// Register a service in the Authentication Service and returns the generated API KEY
func Register(c *cli.Context) error {

	redisCnf = new(strut.RedisConfig)
	//loads redis config
	if err := uti.LoadConfigFile(c.String("redis-file"), redisCnf); err != nil {
		printErrorAndExit(err)
	}
	redisC := redis.New(redisCnf)

	// Try to find the service key, if already exists
	sName := c.String("service")
	if sName == "" {
		printErrorAndExit(fmt.Errorf("Flag service must be specified"))
	}

	k := fmt.Sprintf(redisCnf.APIKey, sName)
	fmt.Printf("%s \n", k)
	v, err := redisC.FindAPIKey(k)
	if err != nil {
		printErrorAndExit(err)
	}

	if v != "" {
		printAndExit(fmt.Sprintf("Existant API KEY for service %s: %s", sName, v))
	}

	// Not found lets create a Key and return it
	vt, err := uuid.NewRandom()
	if err != nil {
		printErrorAndExit(err)
	}

	//Save the Key to REDIS
	if err := redisC.CreateAPIKey(k, vt.String()); err != nil {
		printErrorAndExit(err)
	}

	printAndExit(fmt.Sprintf("API KEY for service %s: %s", sName, vt.String()))

	return nil
}

func printErrorAndExit(err error) {
	fmt.Printf("%s %s\n", color.Red("[ERROR]"), err.Error())
	cli.OsExiter(1)
}

func printAndExit(msg string) {
	fmt.Printf("%s %s\n", color.Green("[RESULT]"), msg)
	cli.OsExiter(0)
}
