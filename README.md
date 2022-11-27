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

http://localhost:8081/accessToken
http://localhost:8081/refreshToken
http://localhost:8081/refreshToken/refresh

http://localhost:8082/accessToken
http://localhost:8082/refreshToken
http://localhost:8082/refreshToken/refresh

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
