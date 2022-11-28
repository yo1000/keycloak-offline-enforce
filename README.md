Keycloak Offline Support
========================

This PoC verifies that the authentication state can be kept up by using offline tokens and others 
in case the session is lost caused by a Keycloak node restart.


Requirements
------------

* Java 11
* Docker


How to run
----------

```shell
kill $(ps aux | grep -v grep | grep keycloak-client-demo | awk '{print $2}')
docker compose down

./mvnw clean package
docker compose up --build &

RETRY_MAX=10
for i in {1..$RETRY_MAX}; do
  if [[ $(curl -s 'http://localhost:8080/auth/realms/demo/.well-known/openid-configuration') &&  -n "$(docker compose ps | grep -v grep | grep config-script | grep exited)" ]]; then
    READY="1"
    break
  else
    echo "Wait for 10s ($i)"
    sleep 10
  fi
done
if [[ "${READY}" -eq "1" ]]; then
  echo "Ready"
  SERVER_PORT=8081 SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENTID=demo1 java -jar keycloak-client-demo/target/keycloak-client-demo-1.0.0.jar &
  SERVER_PORT=8082 SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENTID=demo2 java -jar keycloak-client-demo/target/keycloak-client-demo-1.0.0.jar &
else
  echo "Please try run demo-client after wait a moment."
fi
```


Validate offline support (Browser based)
----------------------------------------

The following have been set up as Demo user.

| Username | Password   |
|:---------|:-----------|
| `demo`   | `demo1234` |

The following have been set up as resource endpoints in Relying Party.

* http://localhost:8080/auth/realms/demo/account
* http://localhost:8081/accessToken
* http://localhost:8081/refreshToken
* http://localhost:8081/refreshToken/refresh
* http://localhost:8082/accessToken
* http://localhost:8082/refreshToken
* http://localhost:8082/refreshToken/refresh

### First. Validate RefreshToken and refresh

1. Access to http://localhost:8081/refreshToken
2. Sign-on by Demo user
3. Access to http://localhost:8081/refreshToken/refresh

### Second. Validate SSO

1. Access to http://localhost:8082/refreshToken
2. Sign-on form can be skipped

### Third. Restart Keycloak node

1. Run command. `docker kill $(docker container ls | grep keycloak | grep '0.0.0.0:8080->8080/tcp' | awk '{print $1}')`
2. Run command. `docker compose up keycloak`

### Fourth. Validate token-refresh.

1. Access to http://localhost:8081/refreshToken/refresh
2. If the sign-on form could be skipped, then the offline support is working effectively

### Fifth. Validate Single-Sign-Off

1. Access to http://localhost:8080/auth/realms/demo/account
2. Click the "Sign out" link in the upper right corner of the screen
3. Access to http://localhost:8081/refreshToken/refresh
4. If the sign-on form could not be skipped, then the single-sign-off is working effectively


Validate offline support (CLI based)
------------------------------------

The following have been set up as Demo user.

| Username | Password   |
|:---------|:-----------|
| `demo`   | `demo1234` |

### First. Validate RefreshToken and refresh

1. Run following commands. If different refresh tokens are returned, then the token-refresh is working effectively

```shell
REFRESH_TOKEN=$(curl -s \
  -XPOST \
  -d "client_id=demo1" \
  -d "grant_type=password" \
  -d "scope=openid+offline_access" \
  -d "username=demo" \
  -d "password=demo1234" \
  "http://localhost:8080/auth/realms/demo/protocol/openid-connect/token" \
| jq -r '.refresh_token')

REFRESH_TOKEN_NEW=$(curl -s \
  -X POST \
  -d client_id=demo1 \
  -d refresh_token=$REFRESH_TOKEN \
  -d grant_type=refresh_token \
  -d scope=openid \
  "http://localhost:8080/auth/realms/demo/protocol/openid-connect/token" \
| jq -r '.refresh_token')

echo $REFRESH_TOKEN
echo $REFRESH_TOKEN_NEW
```

### Second. Restart Keycloak node

1. Run command. `docker kill $(docker container ls | grep keycloak | grep '0.0.0.0:8080->8080/tcp' | awk '{print $1}')`
2. Run command. `docker compose up keycloak`

### Third. Validate token-refresh.

1. Run following commands. If different refresh tokens are returned, then the offline support and token-refresh are working effectively

```shell
REFRESH_TOKEN_RENEW=$(curl -s \
  -X POST \
  -d client_id=demo1 \
  -d refresh_token=$REFRESH_TOKEN_NEW \
  -d grant_type=refresh_token \
  -d scope=openid \
  "http://localhost:8080/auth/realms/demo/protocol/openid-connect/token" \
| jq -r '.refresh_token')

echo $REFRESH_TOKEN_NEW
echo $REFRESH_TOKEN_RENEW
```
