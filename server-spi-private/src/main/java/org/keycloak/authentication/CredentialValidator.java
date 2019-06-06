package org.keycloak.authentication;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;

import java.util.List;

public interface CredentialValidator<T extends CredentialProvider> {
    public T getCredentialProvider(AuthenticationFlowContext context);
    default public List<CredentialModel> getCredentials(AuthenticationFlowContext context) {
        return context.getSession().userCredentialManager().getStoredCredentialsByType(context.getRealm(), context.getUser(), getCredentialProvider(context).getType());
    }
}
