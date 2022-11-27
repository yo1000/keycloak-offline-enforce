#!/usr/bin/env bash

COOKIE_JAR=/tmp/cookiejar

KC_ACCESS_TOKEN=$(curl \
  -XPOST -s \
  -c "${COOKIE_JAR_PATH}" \
  -b "${COOKIE_JAR_PATH}" \
  "${KEYCLOAK_URI_BASE}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" \
  -d "grant_type=password" \
  -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
| jq -r ".access_token")

cat /tmp/realm-export.json | curl \
  -XPOST -s \
  -c "${COOKIE_JAR_PATH}" \
  -b "${COOKIE_JAR_PATH}" \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KEYCLOAK_URI_BASE}/admin/realms/" \
  --data @-

curl \
  -XPOST -s \
  -c "${COOKIE_JAR_PATH}" \
  -b "${COOKIE_JAR_PATH}" \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KEYCLOAK_URI_BASE}/admin/realms/demo/users" \
  -d '{
    "username"      : "demo",
    "email"         : "demo@localhost",
    "firstName"     : "Demo",
    "lastName"      : "User",
    "enabled"       : true,
    "emailVerified" : true,
    "credentials" : [{
      "type"        : "password",
      "temporary"   : false,
      "value"       : "demo1234"
    }]
  }'

echo "Setup is done.

| Username | Password |
|----------|----------|
| demo     | demo1234 |
"
