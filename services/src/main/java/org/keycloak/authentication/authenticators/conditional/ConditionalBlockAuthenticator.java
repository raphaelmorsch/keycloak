package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;

public interface ConditionalBlockAuthenticator extends Authenticator {
    boolean matchCondition(AuthenticationFlowContext context);
}
