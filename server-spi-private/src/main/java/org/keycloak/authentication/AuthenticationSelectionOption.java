package org.keycloak.authentication;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticationExecutionModel;

public class AuthenticationSelectionOption {
    private final AuthenticationExecutionModel authExec;
    private final CredentialModel credential;
    private boolean showCredentialName = true;
    private boolean showCredentialType = true;

    public AuthenticationSelectionOption(AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        this.credential = new CredentialModel();
    }

    public AuthenticationSelectionOption(AuthenticationExecutionModel authExec, CredentialModel credential) {
        this.authExec = authExec;
        this.credential = credential;
    }

    public void setShowCredentialName(boolean showCredentialName) {
        this.showCredentialName = showCredentialName;
    }
    public void setShowCredentialType(boolean showCredentialType) {
        this.showCredentialType = showCredentialType;
    }

    public boolean showCredentialName(){
        if (credential.getId() == null) {
            return false;
        }
        return showCredentialName;
    }

    public boolean showCredentialType(){
        return showCredentialType;
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
        StringBuilder sb = new StringBuilder();
        if (showCredentialName()) {
            if (showCredentialType()) {
                sb.append(" - ");
            }
            if (credential.getUserLabel() == null || credential.getUserLabel().isEmpty()) {
                sb.append(credential.getId());
            } else {
                sb.append(credential.getUserLabel());
            }
        }
        return sb.toString();
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
