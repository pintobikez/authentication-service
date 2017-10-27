package main

import (
	"gopkg.in/urfave/cli.v1"
	"os"
)

var (
	appName = "authentication-service"
	version = "0.0.1"
)

func main() {
	app := cli.NewApp()
	app.Name = appName
	app.Version = version
	app.Copyright = "(c) 2017 - Ricardo Pinto"
	app.Usage = "Simple Authentication Service that checks user Login againts an LDAP"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "listen, l",
			Value:  "0.0.0.0:8000",
			Usage:  "Address and port on which the Service will accept HTTP requests",
			EnvVar: "LISTEN",
		},
		cli.StringFlag{
			Name:   "log-folder, lf",
			Value:  "",
			Usage:  `Log folder path for access and application logging. Default "stdout"`,
			EnvVar: "LOG_FOLDER",
		},
		cli.StringFlag{
			Name:   "newrelic-appname",
			Value:  app.Name,
			Usage:  "NewRelic application name, this flag is required for NewRelic instrumentation",
			EnvVar: "NEWRELIC_APPNAME",
		},
		cli.StringFlag{
			Name:   "newrelic-license-key",
			Value:  "",
			Usage:  "NewRelic license key, this flag is required for NewRelic instrumentation",
			EnvVar: "NEWRELIC_LICENSE_KEY",
		},
		cli.StringFlag{
			Name:   "revision-file",
			Value:  "",
			Usage:  "Expose the revision file generated by build into url",
			EnvVar: "REVISION_FILE",
		},
		cli.StringFlag{
			Name:   "ldap-file, secf",
			Value:  "",
			Usage:  "LDAP configuration used by the Service to connect to the corporate LDAP",
			EnvVar: "LDAP_FILE",
		},
		cli.StringFlag{
			Name:   "security-file, sf",
			Value:  "",
			Usage:  "Security configuration",
			EnvVar: "SECURITY_FILE",
		},
		cli.StringFlag{
			Name:   "redis-file, rf",
			Value:  "",
			Usage:  "Redis configuration",
			EnvVar: "REDIS_FILE",
		},
		cli.StringFlag{
			Name:   "swagger-file",
			Value:  "",
			Usage:  "Expose the swagger file",
			EnvVar: "SWAGGER_FILE",
		},
		cli.StringFlag{
			Name:   "ssl-cert",
			Value:  "",
			Usage:  "Define SSL certificate to accept HTTPS requests",
			EnvVar: "SSL_CERT",
		},
		cli.StringFlag{
			Name:   "ssl-key",
			Value:  "",
			Usage:  "Define SSL key to accept HTTPS requests",
			EnvVar: "SSL_KEY",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:   "register",
			Usage:  "Register a service and returns an API Key for the service",
			Action: Register,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "service",
					Usage:  "The name of the service to register",
					Value:  "",
					EnvVar: "service",
				},
				cli.StringFlag{
					Name:   "redis-file",
					Value:  "",
					Usage:  "Redis configuration",
					EnvVar: "REDIS_FILE",
				},
			},
		},
	}

	app.Action = Handler

	app.Run(os.Args)
}
