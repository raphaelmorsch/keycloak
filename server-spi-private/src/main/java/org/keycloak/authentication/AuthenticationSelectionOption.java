package org.keycloak.authentication;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticationExecutionModel;

public class AuthenticationSelectionOption {
    private final AuthenticationExecutionModel authExec;
    private final CredentialModel credential;
    private boolean showCredentialName = true;

    public AuthenticationSelectionOption(AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        this.credential = new CredentialModel();
    }

    public AuthenticationSelectionOption(AuthenticationExecutionModel authExec, CredentialModel credential) {
        this.authExec = authExec;
        this.credential = credential;
    }

    public AuthenticationSelectionOption setShowCredentialName(boolean showCredentialName) {
        this.showCredentialName = showCredentialName;
        return this;
    }

    public boolean showCredentialName(){
        if (credential.getId() == null) {
            return false;
        }
        return showCredentialName;
    }

    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getCredentialId(){
        return credential.getId();
    }

    public String getAuthExecId(){
        return authExec.getId();
    }

    public String getCredentialName() {
        return credential.getUserLabel();
    }

    public String getAuthExecName() {
        return authExec.getAuthenticator();
    }

    public String getId() {
        if (getCredentialId() == null) {
            return getAuthExecId() + "|";
        }
        return getAuthExecId() + "|" + getCredentialId();
    }
}
