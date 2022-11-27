FROM jboss/keycloak:9.0.3

USER root

ENV PROVIDERS_HOME=/opt/jboss/keycloak/providers

COPY ./target/keycloak-offline-enforce.jar $PROVIDERS_HOME/keycloak-offline-enforce.jar
