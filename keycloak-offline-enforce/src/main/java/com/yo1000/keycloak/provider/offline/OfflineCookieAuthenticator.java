package com.yo1000.keycloak.provider.offline;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.DisplayTypeAuthenticatorFactory;
import org.keycloak.authentication.authenticators.AttemptedAuthenticator;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.Cookie;
import java.util.List;

public class OfflineCookieAuthenticator extends CookieAuthenticator implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {
    protected static final Logger logger = Logger.getLogger(OfflineCookieAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationManager.AuthResult authResult = authenticateOfflineIdentityCookie(
                context.getSession(), context.getRealm(), true);

        if (authResult == null) {
            context.attempted();
        } else {
            AuthenticationSessionModel clientSession = context.getAuthenticationSession();
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, clientSession.getProtocol());

            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), clientSession)) {
                context.attempted();
            } else {
                context.getSession().setAttribute(org.keycloak.services.managers.AuthenticationManager.SSO_AUTH, "true");
                context.setUser(authResult.getUser());
                // Intentionally not attaching.
                //context.attachUserSession(authResult.getSession());
                context.success();
            }
        }
    }

    private AuthenticationManager.AuthResult authenticateOfflineIdentityCookie(
            KeycloakSession session, RealmModel realm, boolean checkActive
    ) {
        Cookie cookie = CookieHelper.getCookie(session.getContext().getRequestHeaders().getCookies(), AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);
        if (cookie == null || "".equals(cookie.getValue())) {
            logger.debugv("Could not find cookie: {0}", AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);
            return null;
        }

        final boolean IS_COOKIE = false;

        String tokenString = cookie.getValue();
        AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(
                session, realm, session.getContext().getUri(), session.getContext().getConnection(),
                checkActive, false, IS_COOKIE, tokenString, session.getContext().getRequestHeaders(),
                new TokenVerifier.TokenTypeCheck(TokenUtil.TOKEN_TYPE_KEYCLOAK_ID));

        if (authResult == null) {
            AuthenticationManager.expireIdentityCookie(realm, session.getContext().getUri(),
                    session.getContext().getConnection());
            AuthenticationManager.expireOldIdentityCookie(realm, session.getContext().getUri(),
                    session.getContext().getConnection());
            return null;
        }

        authResult.getSession().setLastSessionRefresh(Time.currentTime());
        return authResult;
    }

    @Override
    public void close() {
        // NOP
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
    public String getId() {
        return "offline-cookie";
    }

    @Override
    public String getDisplayType() {
        return "Offline Cookie";
    }

    @Override
    public String getReferenceCategory() {
        return getId();
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
    public Authenticator createDisplay(KeycloakSession keycloakSession, String displayType) {
        if (displayType == null) return this;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return AttemptedAuthenticator.SINGLETON;  // ignore this authenticator
    }

    @Override
    public String getHelpText() {
        return "Validates the SSO <Offline> cookie set by the auth server.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
