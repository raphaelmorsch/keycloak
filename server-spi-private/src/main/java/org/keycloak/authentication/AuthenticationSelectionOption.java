package org.keycloak.authentication;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class AuthenticationSelectionOption {

    private final KeycloakSession session;
    private final AuthenticationExecutionModel authExec;

    public AuthenticationSelectionOption(KeycloakSession session, AuthenticationExecutionModel authExec) {
        this.session = session;
        this.authExec = authExec;
    }


    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getAuthExecId(){
        return authExec.getId();
    }

    public String getAuthExecName() {
        return authExec.getAuthenticator();
    }

    public String getAuthExecDisplayName() {

        return getAuthExecName();
        // TODO:mposolda Retrieve the displayName for the authenticator from the AuthenticationFactory
        // TODO:mposolda Retrieve icon CSS style
    }


    @Override
    public String toString() {
        return " authSelection - " + authExec.getAuthenticator();
    }
}
