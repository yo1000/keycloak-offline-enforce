package com.yo1000.keycloak.provider.offline;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class OfflineScopeEnforceAuthenticator implements Authenticator, AuthenticatorFactory {
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        try {
            String scope = authenticationFlowContext.getAuthenticationSession().getClientNote("scope");

            if (!scope.contains("offline_access")) {
                authenticationFlowContext.getAuthenticationSession().setClientNote("scope", scope + " offline_access");
            }

            authenticationFlowContext.attempted();
        } catch (Exception e) {
            // NOP
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        // NOP
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // NOP
    }

    @Override
    public String getDisplayType() {
        return "Offline Scope Enforce";
    }

    @Override
    public String getReferenceCategory() {
        return getDisplayType();
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "When enabled, similar behavior as request with offline_access scope.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return this;
    }

    @Override
    public void init(Config.Scope scope) {
        // NOP
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // NOP
    }

    @Override
    public void close() {
        // NOP
    }

    @Override
    public String getId() {
        return "offline-scope-enforce";
    }
}
