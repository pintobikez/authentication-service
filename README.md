# Authentication Service
Simple LDAP Authentication Service, that connects to corporate LDAP and checks if the user can Login.
If the groups that are to be checked are passed to, it will check if the user has access to them.
If the user can Login it generates a Token which is retrieved in the response.
It returns the username, groups where it is present and the session token.
Token validity can be checked to by using the token endpoint

## Requirements
App requires Golang 1.8 or later, Glide Package Manager and Docker (for building)

## Installation
- Install [Golang](https://golang.org/doc/install)
- Install [Glide](https://glide.sh)
- Install [Docker](https://docker.com)


## Build
For building binaries please use make, look at the commands bellow:

```
// Build the binary in your environment
$ make build

// Build with another OS. Default Linux
$ make OS=darwin build

// Build with custom version.
$ make APP_VERSION=0.1.0 build

// Build with custom app name.
$ make APP_NAME=authentication-service build

// Passing all flags
$ make OS=darwin APP_NAME=authentication-service-docker APP_VERSION=0.1.0 build

// Clean Up
$ make clean

// Configure. Install app dependencies.
$ make configure

// Check if docker exists.
$ make depend

// Create a docker image with application
$ make pack

// Pack with custom version.
$ make APP_VERSION=0.1.0 pack

// Pack with custom app name.
$ make APP_NAME=authentication-service pack

// Pack passing all flags
$ make APP_NAME=authentication-service-docker APP_VERSION=0.1.0
```

## Development
```
// Running tests
$ make test

// Running tests with coverage. Output coverage file: coverage.html
$ make test-coverage

// Running tests with junit report. Output coverage file: report.xml
$ make test-report
```

## Run it
Build it
```
$ make build
```
Launch redis:
```
$ docker run --name redis-auth -d redis

```
Run the service with LDAP:
```
$ ./build/authentication-service --rf core.redisconfig.yml.example --sf core.securityconfig.yml.example --secf core.ldapconfig.yml.example --listen 0.0.0.0:8081

```
Run the service with Mocked LDAP (note that the GROUP_TO_CHECK in the login call must be: mock):
```
$ ./build/authentication-service --rf core.redisconfig.yml.example --sf core.securityconfig.yml.example --listen 0.0.0.0:8081 --noldap

```

## Configuration:
There are 3 files used for configuration:
- SECURITY_FILE: you must supply a 32 characters cipher key
- LDAP_FILE: LDAP connection configuration
- REDIS_FILE: REDIS connection configuration

## Usage:

# Register a service:
Run in the server terminal the following
```
$ ./BUILD_PATH/authentication-service register --service SERVICENAME_CALLING_AUTH --redis-file REDIS_CONFIG_FILE
```

# Delete a service:
Run in the server terminal the following
```
$ ./BUILD_PATH/authentication-service register remove --service SERVICENAME_CALLING_AUTH --redis-file REDIS_CONFIG_FILE
```

# Perform User Login
```
curl -v -X POST http://127.0.0.1:8080/authenticate -H 'content-type:application/json' -d '{"username":"USERNAME","password":"USER_PASSWORD","service":"SERVICENAME_CALLING_AUTH","groups":["GROUP_TO_CHECK"]}'
```
# Check User Login
```
curl -v -X POST http://127.0.0.1:8080/validate -H 'AuthorizationRequestBy:SERVICENAME_CALLING_AUTH' -H 'Authorization:TOKEN'
```
# Check Service Health
```
curl -v -X GET http://127.0.0.1:8080/health/
```
