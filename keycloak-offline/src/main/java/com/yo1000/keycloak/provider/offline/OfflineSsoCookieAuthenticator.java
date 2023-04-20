package com.yo1000.keycloak.provider.offline;

import org.jboss.logging.Logger;
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
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.*;

public class OfflineSsoCookieAuthenticator extends CookieAuthenticator implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {
    public static final String KEYCLOAK_IDENTITY_REMEMBER_COOKIE =
            AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE + "_REMEMBER";

    public static final String USER_ATTR_OFFLINE_COOKIE_FORCE_EXPIRY =
            "cookie.offline.force-expiry";

    private static final String AUTH_NOTE_OFFLINE_COOKIE_AUTHENTICATED =
            "cookie.offline.authenticated";

    private static final String CONFIG_PROPS_COOKIE_DOMAIN =
            "cookie.offline.domain";

    private static final String CONFIG_PROPS_COOKIE_PATH =
            "cookie.offline.path";

    private static final String CONFIG_PROPS_COOKIE_SECURE =
            "cookie.offline.secure";

    private static final List<ProviderConfigProperty> configProps = List.of(new ProviderConfigProperty(
            CONFIG_PROPS_COOKIE_DOMAIN,
            "Cookie domain",
            "Domain attribute of KEYCLOAK_IDENTITY_REMEMBER cookie",
            ProviderConfigProperty.STRING_TYPE,
            ""
    ), new ProviderConfigProperty(
            CONFIG_PROPS_COOKIE_PATH,
            "Cookie path",
            "Path attribute of KEYCLOAK_IDENTITY_REMEMBER cookie",
            ProviderConfigProperty.STRING_TYPE,
            ""
    ), new ProviderConfigProperty(
            CONFIG_PROPS_COOKIE_SECURE,
            "Cookie secure",
            "Secure attribute of KEYCLOAK_IDENTITY_REMEMBER cookie",
            ProviderConfigProperty.BOOLEAN_TYPE,
            true
    ));

    private final Logger logger = Logger.getLogger(OfflineSsoCookieAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final HttpRequest request = context.getHttpRequest();

        final Map<String, String> config = Optional
                .ofNullable(context.getAuthenticatorConfig())
                .map(AuthenticatorConfigModel::getConfig)
                .orElse(Collections.emptyMap());

        final String cookieDomain = Optional
                .of(config.getOrDefault(CONFIG_PROPS_COOKIE_DOMAIN, ""))
                .filter(v -> !v.isEmpty())
                .orElse(context.getUriInfo().getBaseUri().getHost());

        final String cookiePath = Optional
                .of(config.getOrDefault(CONFIG_PROPS_COOKIE_PATH, ""))
                .filter(v -> !v.isEmpty())
                .orElse(MessageFormat.format("{0}/realms/{1}/",
                        context.getUriInfo().getBaseUri().getPath().replaceFirst("/$", ""),
                        context.getRealm().getName()));

        final boolean cookieSecure = config
                .getOrDefault(CONFIG_PROPS_COOKIE_SECURE, Boolean.TRUE.toString())
                .equals(Boolean.TRUE.toString());

        logger.debugv("Config {0}={1}", CONFIG_PROPS_COOKIE_DOMAIN, cookieDomain);
        logger.debugv("Config {0}={1}", CONFIG_PROPS_COOKIE_PATH, cookiePath);
        logger.debugv("Config {0}={1}", CONFIG_PROPS_COOKIE_SECURE, cookieSecure);

        final Cookie keycloakSessionCookie = extractCookie(request, AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
        final Cookie keycloakIdentityCookie = extractCookie(request, AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);
        final Cookie keycloakIdentityRememberCookie = extractCookie(request, KEYCLOAK_IDENTITY_REMEMBER_COOKIE);

        logger.debugv("Cookie {0}", keycloakSessionCookie);
        logger.debugv("Cookie {0}", keycloakIdentityCookie);
        logger.debugv("Cookie {0}", keycloakIdentityRememberCookie);

        // When all cookies affecting OfflineCookieAuthenticator are null,
        // then it will be delegated on to next execution in flow.
        if (keycloakSessionCookie == null && keycloakIdentityCookie == null && keycloakIdentityRememberCookie == null) {
            logger.debug("When all cookies affecting OfflineCookieAuthenticator are null");
            context.attempted();
            return;
        }

        // When KEYCLOAK_SESSION cookie is null,
        // then it will be redirected to self with dispose all cookies affecting OfflineCookieAuthenticator.
        // e.g., after a logout operation.
        if (isEmptyCookie(keycloakSessionCookie)) {
            logger.debugv("When {0} cookie is null", AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
            handleMissingKeycloakSession(context, cookieDomain, cookiePath, cookieSecure);
            return;
        }

        // When cookie.offline.force-expiry user attribute is found and is detected expired offline identity token by compared it,
        // then it will be redirected to self with dispose all cookies affecting OfflineCookieAuthenticator.
        if (isKeycloakIdentityCookieForceExpiry(context, keycloakIdentityCookie)) {
            logger.debugv("When {0} user attribute is found and is detected expired {1} cookie's token",
                    USER_ATTR_OFFLINE_COOKIE_FORCE_EXPIRY,
                    AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);
            expireKeycloakIdentityCookie(context, cookieDomain, cookiePath, cookieSecure);
            return;
        }

        // When cookie.offline.force-expiry user attribute is found and is detected expired offline identity token by compared it,
        // then it will be redirected to self with dispose all cookies affecting OfflineCookieAuthenticator.
        if (isKeycloakIdentityCookieForceExpiry(context, keycloakIdentityRememberCookie)) {
            logger.debugv("When {0} user attribute is found and is detected expired {1} cookie's token",
                    USER_ATTR_OFFLINE_COOKIE_FORCE_EXPIRY,
                    KEYCLOAK_IDENTITY_REMEMBER_COOKIE);
            expireKeycloakIdentityCookie(context, cookieDomain, cookiePath, cookieSecure);
            return;
        }

        // When KEYCLOAK_IDENTITY_REMEMBER cookie is found and is valid,
        // then it will be flow status to Success.
        if (!isEmptyCookie(keycloakIdentityRememberCookie)) {
            logger.debugv("When {0} cookie is found", KEYCLOAK_IDENTITY_REMEMBER_COOKIE);
            handleKeycloakIdentityRememberCookie(context, keycloakIdentityRememberCookie,
                    cookieDomain, cookiePath, cookieSecure);
            return;
        }

        // When KEYCLOAK_IDENTITY cookie is found and is valid,
        // then it will be redirected to self with copy to KEYCLOAK_IDENTITY_REMEMBER cookie.
        if (!isEmptyCookie(keycloakIdentityCookie)) {
            logger.debugv("When {0} cookie is found", AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE);
            handleKeycloakIdentityCookie(context, keycloakIdentityCookie,
                    cookieDomain, cookiePath, cookieSecure);
            return;
        }

        // When others,
        // then it will be delegated on to next execution in flow.
        logger.debug("When others");
        context.attempted();
    }

    private void handleMissingKeycloakSession(
            AuthenticationFlowContext context,
            String cookieDomain, String cookiePath, boolean secure) {
        context.challenge(Response
                .status(Response.Status.FOUND)
                .location(context.getRefreshUrl(false))
                .cookie(expiresCookie(cookieDomain, cookiePath, secure,
                        AuthenticationManager.KEYCLOAK_SESSION_COOKIE,
                        AuthenticationManager.KEYCLOAK_IDENTITY_COOKIE,
                        KEYCLOAK_IDENTITY_REMEMBER_COOKIE))
                .build()
        );
    }

    private boolean isKeycloakIdentityCookieForceExpiry(
            AuthenticationFlowContext context, Cookie cookie) {
        AuthenticationManager.AuthResult authResult = Optional
                .ofNullable(cookie)
                .map(c -> reconstructAuthResult(context.getSession(), context.getRealm(), c.getValue()))
                .orElse(null);

        if (authResult == null) {
            return false;
        }

        UserModel user = authResult.getUser();

        // Illegal state
        if (user == null) {
            return true;
        }

        String userAttrExpiration = user.getFirstAttribute(USER_ATTR_OFFLINE_COOKIE_FORCE_EXPIRY);

        if (userAttrExpiration == null || !userAttrExpiration.matches("\\d+")) {
            return false;
        }

        // Expired
        return authResult.getToken().getIat() <= Long.parseLong(userAttrExpiration);
    }

    private void expireKeycloakIdentityCookie(
            AuthenticationFlowContext context,
            String cookieDomain, String cookiePath, boolean secure) {
        context.challenge(Response
                .status(Response.Status.FOUND)
                .location(context.getRefreshUrl(false))
                .cookie(expiresCookie(cookieDomain, cookiePath, secure,
                        AuthenticationManager.KEYCLOAK_SESSION_COOKIE))
                .build()
        );
    }

    private void handleKeycloakIdentityCookie(
            AuthenticationFlowContext context, Cookie cookie,
            String cookieDomain, String cookiePath, boolean secure) {
        if (extractUserFromKeycloakIdentityCookie(context, cookie, cookieDomain, cookiePath, secure) != null) {
            context.challenge(Response
                    .status(Response.Status.FOUND)
                    .location(context.getRefreshUrl(false))
                    .cookie(new NewCookie(
                            KEYCLOAK_IDENTITY_REMEMBER_COOKIE,
                            cookie.getValue(),
                            cookiePath,
                            cookieDomain,
                            "",
                            context.getRealm().getSsoSessionIdleTimeoutRememberMe(),
                            secure,
                            true))
                    .build()
            );
        }
    }

    private void handleKeycloakIdentityRememberCookie(
            AuthenticationFlowContext context, Cookie cookie,
            String cookieDomain, String cookiePath, boolean secure) {
        UserModel user = extractUserFromKeycloakIdentityCookie(context, cookie, cookieDomain, cookiePath, secure);

        // Illegal state
        if (user == null) {
            return;
        }

        if (Optional.ofNullable(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OFFLINE_COOKIE_AUTHENTICATED))
                .map(authenticated -> authenticated.equals(Boolean.TRUE.toString()))
                .orElse(false)) {
            context.setUser(user);
            context.success();
        } else {
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OFFLINE_COOKIE_AUTHENTICATED, Boolean.TRUE.toString());
            context.challenge(Response
                    .status(Response.Status.FOUND)
                    .location(context.getRefreshUrl(false))
                    .cookie(new NewCookie(
                            KEYCLOAK_IDENTITY_REMEMBER_COOKIE,
                            cookie.getValue(),
                            cookiePath,
                            cookieDomain,
                            "",
                            context.getRealm().getSsoSessionIdleTimeoutRememberMe(),
                            secure,
                            true))
                    .build()
            );
        }
    }

    private UserModel extractUserFromKeycloakIdentityCookie(
            AuthenticationFlowContext context, Cookie cookie,
            String cookieDomain, String cookiePath, boolean secure
    ) {
        AuthenticationManager.AuthResult authResult = Optional
                .ofNullable(cookie)
                .map(c -> reconstructAuthResult(context.getSession(), context.getRealm(), c.getValue()))
                .orElse(null);

        // Illegal state
        if (authResult == null) {
            context.challenge(Response
                    .status(Response.Status.FOUND)
                    .location(context.getRefreshUrl(false))
                    .cookie(expiresCookie(cookieDomain, cookiePath, secure,
                            AuthenticationManager.KEYCLOAK_SESSION_COOKIE))
                    .build()
            );
            return null;
        }

        UserModel user = authResult.getUser();

        // Illegal state
        if (user == null) {
            context.challenge(Response
                    .status(Response.Status.FOUND)
                    .location(context.getRefreshUrl(false))
                    .cookie(expiresCookie(cookieDomain, cookiePath, secure,
                            AuthenticationManager.KEYCLOAK_SESSION_COOKIE))
                    .build()
            );
            return null;
        }

        return user;
    }

    private NewCookie[] expiresCookie(String domain, String path, boolean secure, String... names) {
        return Arrays.stream(names)
                .filter(Objects::nonNull)
                .map(n -> {
                    return new NewCookie(
                            n,      // Name
                            null,   // Value
                            path,   // Path
                            domain, // Domain
                            "",     // Comment
                            0,      // MaxAge
                            secure, // Secure
                            true    // HttpOnly
                    );
                })
                .toArray(NewCookie[]::new);
    }

    private boolean isEmptyCookie(Cookie cookie) {
        return cookie == null || cookie.getValue() == null || cookie.getValue().isEmpty();
    }

    private Cookie extractCookie(HttpRequest request, String name) {
        return extractOptionalCookie(request, name).orElse(null);
    }

    private Optional<Cookie> extractOptionalCookie(HttpRequest request, String name) {
        return request.getHttpHeaders()
                .getCookies()
                .values()
                .stream()
                .filter(cookie -> cookie.getName().equals(name) && !cookie.getValue().isEmpty())
                .findFirst();
    }

    private AuthenticationManager.AuthResult reconstructAuthResult(
            KeycloakSession session, RealmModel realm, String jwt) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(
                session, realm, session.getContext().getUri(), session.getContext().getConnection(),
                false,  // checkActive
                false,  // checkTokenType
                false,  // isCookie
                jwt, session.getContext().getRequestHeaders(),
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
        return "offline-sso-cookie";
    }

    @Override
    public String getDisplayType() {
        return "Offline SSO Cookie";
    }

    @Override
    public String getReferenceCategory() {
        return getId();
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return configProps;
    }
}
