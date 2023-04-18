package com.yo1000.keycloak.provider.offline;

import org.jboss.resteasy.spi.HttpRequest;
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
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;

public class OfflineCookieAuthenticator extends CookieAuthenticator implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {
    public static final String KEYCLOAK_IDENTITY_REMEMBER_COOKIE =
            AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE + "_REMEMBER";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // When KEYCLOAK_SESSION cookie is destroyed,
        // KEYCLOAK_IDENTITY_REMEMBER cookie must also be destroyed,
        // since sign-out is considered to have occurred.
        if (context.getHttpRequest().getHttpHeaders().getCookies().keySet().stream()
                .noneMatch(cookieName -> cookieName.equals(AuthenticationManager.KEYCLOAK_SESSION_COOKIE))) {
            Cookie keycloakIdentityRememberCookie = extractCookie(context.getHttpRequest(),
                    KEYCLOAK_IDENTITY_REMEMBER_COOKIE);

            if (keycloakIdentityRememberCookie != null) {
                // <Challenge>
                context.challenge(Response
                        .temporaryRedirect(context.getRefreshUrl(false))
                        .cookie(new NewCookie(
                                keycloakIdentityRememberCookie.getName(),
                                keycloakIdentityRememberCookie.getValue(),
                                keycloakIdentityRememberCookie.getPath(),
                                keycloakIdentityRememberCookie.getDomain(),
                                "",
                                0,
                                false,
                                false
                        ))
                        .build()
                );
            } else {
                // <Attempted>
                context.attempted();
            }

            return;
        }

        Cookie keycloakIdentityRememberCookie = extractCookie(context.getHttpRequest(),
                KEYCLOAK_IDENTITY_REMEMBER_COOKIE);

        if (!isEmptyValue(keycloakIdentityRememberCookie)) {
            AuthenticationManager.AuthResult authResult = reconstructAuthResult(
                    context.getSession(), context.getRealm(), false,
                    keycloakIdentityRememberCookie.getValue());

            // <Challenge>
            // When user matching KEYCLOAK_IDENTITY_REMEMBER cookie cannot be found,
            // The cookie is disposed and user is redirected to Sign-on.
            if (authResult == null) {
                context.challenge(Response
                        .temporaryRedirect(context.getRefreshUrl(false))
                        .cookie(new NewCookie(
                                keycloakIdentityRememberCookie.getName(),
                                keycloakIdentityRememberCookie.getValue(),
                                keycloakIdentityRememberCookie.getPath(),
                                keycloakIdentityRememberCookie.getDomain(),
                                "",
                                0,
                                false,
                                false
                        ))
                        .build()
                );
                return;
            }

            // <Success>
            // When user is found that matches KEYCLOAK_IDENTITY_REMEMBER cookie,
            // it is assumed that user has successfully authenticated.
            context.setUser(authResult.getUser());
            context.success();
            return;
        }

        Cookie keycloakIdentityCookie = extractCookie(context.getHttpRequest(),
                AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);

        // <Attempted>
        // When neither KEYCLOAK_IDENTITY_REMEMBER cookie nor KEYCLOAK_IDENTITY cookie are not existed,
        // user is redirected to sign-in.
        if (isEmptyValue(keycloakIdentityCookie)) {
            context.attempted();
            return;
        }

        AuthenticationManager.AuthResult authResult =  reconstructAuthResult(
                context.getSession(), context.getRealm(), false,
                keycloakIdentityCookie.getValue());

        // <Attempted>
        // When the key corresponding to a KID has been invalidated due to key replacement, etc.,
        // the status will be corrected in a subsequent process,
        // so leave it to the subsequent process and mark ATTEMPTED.
        if (authResult == null) {
            context.attempted();
            return;
        }

        RootAuthenticationSessionModel rootAuthSession = context.getSession().authenticationSessions()
                .getRootAuthenticationSession(context.getRealm(), authResult.getSession().getId());

        if (rootAuthSession != null) {
            context.getSession().authenticationSessions()
                    .removeRootAuthenticationSession(context.getRealm(), rootAuthSession);
        }

        // <Challenge>
        // When user is found using KEYCLOAK_IDENTITY cookie,
        // copy it as KEYCLOAK_IDENTITY_REMEMBER cookie so that it is not lost due to cache volatiles.
        context.challenge(Response
                .temporaryRedirect(context.getRefreshUrl(false))
                .cookie(new NewCookie(
                        KEYCLOAK_IDENTITY_REMEMBER_COOKIE,
                        keycloakIdentityCookie.getValue(),
                        keycloakIdentityCookie.getPath(),
                        keycloakIdentityCookie.getDomain(),
                        "",
                        context.getRealm().getSsoSessionIdleTimeoutRememberMe(),
                        false,
                        false
                ))
                .build()
        );
    }

    private boolean isEmptyValue(Cookie cookie) {
        return cookie == null || cookie.getValue() == null || cookie.getValue().isEmpty();
    }

    private Cookie extractCookie(HttpRequest request, String name) {
        return extractOptionalCookie(request, name).orElse(null);
    }

    private Optional<Cookie> extractOptionalCookie(HttpRequest request, String name) {
        return extractOptionalCookie(request, name, false);
    }

    private Optional<Cookie> extractOptionalCookie(HttpRequest request, String name, boolean allowEmptyValue) {
        return request.getHttpHeaders()
                .getCookies()
                .values()
                .stream()
                .filter(cookie -> cookie.getName().equals(name) && (allowEmptyValue || !cookie.getValue().isEmpty()))
                .findFirst();
    }

    private AuthenticationManager.AuthResult reconstructAuthResult(
            KeycloakSession session, RealmModel realm, boolean checkActive, String jwt) {
        final boolean IS_COOKIE = false;

        AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(
                session, realm, session.getContext().getUri(), session.getContext().getConnection(),
                checkActive, false, IS_COOKIE, jwt, session.getContext().getRequestHeaders(),
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
