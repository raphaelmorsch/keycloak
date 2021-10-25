package org.keycloak.authentication.authenticators.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowCallback;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class ConditionalLoaAuthenticator implements ConditionalAuthenticator, AuthenticationFlowCallback {

    static final String LEVEL = "loa-condition-level";
    static final String STORE_IN_USER_SESSION = "loa-store-in-user-session";

    private static final Logger logger = Logger.getLogger(ConditionalLoaAuthenticator.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        int currentLoa = AuthenticatorUtil.getCurrentLevelOfAuthentication(authSession);
        int requestedLoa = AuthenticatorUtil.getRequestedLevelOfAuthentication(authSession);
        return (currentLoa < Constants.MINIMUM_LOA && requestedLoa < Constants.MINIMUM_LOA)
                || (currentLoa < getConfiguredLoa(context) && currentLoa < requestedLoa);
    }

    @Override
    public void onParentFlowSuccess(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        int currentLoa = Math.max(getConfiguredLoa(context), AuthenticatorUtil.getCurrentLevelOfAuthentication(authSession));
        logger.tracef("Updating LoA to '%d' when authenticating session '%s'", currentLoa, authSession.getParentSession().getId());
        authSession.setAuthNote(Constants.LEVEL_OF_AUTHENTICATION, String.valueOf(currentLoa));
        if (isStoreInUserSession(context)) {
            authSession.setUserSessionNote(Constants.LEVEL_OF_AUTHENTICATION, String.valueOf(currentLoa));
        }
    }

    private int getConfiguredLoa(AuthenticationFlowContext context) {
        try {
            return Integer.parseInt(context.getAuthenticatorConfig().getConfig().get(LEVEL));
        } catch (NullPointerException | NumberFormatException e) {
            logger.errorv("Invalid configuration: {0}", LEVEL);
            return Constants.MAXIMUM_LOA;
        }
    }

    private boolean isStoreInUserSession(AuthenticationFlowContext context) {
        try {
            return Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get(STORE_IN_USER_SESSION));
        } catch (NullPointerException | NumberFormatException e) {
            logger.errorv("Invalid configuration: {0}", STORE_IN_USER_SESSION);
            return false;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) { }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }

    @Override
    public void close() { }
}
