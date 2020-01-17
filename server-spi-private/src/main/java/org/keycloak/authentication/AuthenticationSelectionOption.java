package org.keycloak.authentication;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class AuthenticationSelectionOption {

    private final AuthenticationExecutionModel authExec;
    private final AuthenticatorFactory factory;

    public AuthenticationSelectionOption(KeycloakSession session, AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        this.factory = (AuthenticatorFactory) session.getKeycloakSessionFactory().getProviderFactory(Authenticator.class, authExec.getAuthenticator());
    }


    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getAuthExecId(){
        return authExec.getId();
    }

    public String getUserDisplayName() {
        return factory.getUserDisplayName();
    }

    public String getUserHelpText() {
        return factory.getUserHelpText();
    }

    public String getIconCssClass() {
        return factory.getIconCssClass();
    }


    @Override
    public String toString() {
        return " authSelection - " + authExec.getAuthenticator();
    }
}
