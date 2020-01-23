package org.keycloak.authentication;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class AuthenticationSelectionOption {

    private final AuthenticationExecutionModel authExec;
    private final AuthenticatorFactory factory;
    private final CredentialTypeMetadata credentialTypeMetadata;

    public AuthenticationSelectionOption(KeycloakSession session, AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        this.factory = (AuthenticatorFactory) session.getKeycloakSessionFactory().getProviderFactory(Authenticator.class, authExec.getAuthenticator());
        Authenticator authenticator = this.factory.create(session);
        if (authenticator instanceof CredentialValidator) {
            CredentialProvider credentialProvider = ((CredentialValidator) authenticator).getCredentialProvider(session);
            credentialTypeMetadata = credentialProvider.getCredentialTypeMetadata();
        } else {
            credentialTypeMetadata = null;
        }
    }


    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getAuthExecId(){
        return authExec.getId();
    }

    public String getDisplayName() {
        return credentialTypeMetadata == null ? factory.getDisplayType() : credentialTypeMetadata.getDisplayName();
    }

    public String getHelpText() {
        return credentialTypeMetadata == null ? factory.getHelpText() : credentialTypeMetadata.getHelpText();
    }

    public String getIconCssClass() {
        // For now, we won't allo to retrieve "iconCssClass" from the AuthenticatorFactory. We will see in the future if we need
        // this capability for authenticator factories, which authenticators don't implement credentialProvider
        return credentialTypeMetadata == null ? CredentialTypeMetadata.DEFAULT_ICON_CSS_CLASS : credentialTypeMetadata.getIconCssClass();
    }


    @Override
    public String toString() {
        return " authSelection - " + authExec.getAuthenticator();
    }
}
