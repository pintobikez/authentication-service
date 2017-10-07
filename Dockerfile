FROM alpine:3.5

LABEL maintainer "pinto.bikez@gmail.com"

ARG APP_NAME=authentication-service

RUN apk add --no-cache ca-certificates

ADD ./build/$APP_NAME /app
ADD ./core.ldapconfig.yml.example /core.ldapconfig.yml
ADD ./core.securityconfig.yml.example /core.securityconfig.yml
ADD ./core.redisconfig.yml.example /core.redisconfig.yml

# Environment Variables
ENV LISTEN "0.0.0.0:8080"
ENV LDAP_FILE "core.ldapconfig.yml"
ENV SECURITY_FILE "core.securityconfig.yml"
ENV REDIS_FILE "core.redisconfig.yml"
ENV LOG_FOLDER "/var/log/"

CMD ["/app"]
