package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/gommon/color"
	uti "github.com/pintobikez/authentication-service/config"
	strut "github.com/pintobikez/authentication-service/config/structures"
	"github.com/pintobikez/authentication-service/redis"
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

	sName := c.String("service")
	if sName == "" {
		printErrorAndExit(fmt.Errorf("Flag service must be specified"))
	}

	add := true
	if len(c.Args()) > 0 && c.Args()[0] == "remove" {
		add = false
	}

	// Try to find the service key, if already exists
	k := fmt.Sprintf(redisCnf.APIKey, sName)
	v, err := redisC.FindString(k)
	if err != nil {
		printErrorAndExit(err)
	}

	if v != "" && add {
		printAndExit(fmt.Sprintf("Existant API KEY for service %s: %s", sName, v))
	}

	// Found and is to Delete
	if !add {
		if v != "" {
			if err := redisC.DeleteKey(k); err != nil {
				printErrorAndExit(err)
			}
			printAndExit(fmt.Sprintf("API KEY %s deleted for service %s", v, sName))
		} else {
			printAndExit(fmt.Sprintf("API KEY doesn't exist for service: %s", sName))
		}
	}

	// Not found lets create a Key and return it
	vt, err := uuid.NewRandom()
	if err != nil {
		printErrorAndExit(err)
	}

	//Save the Key to REDIS
	if err := redisC.CreateString(k, vt.String()); err != nil {
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
