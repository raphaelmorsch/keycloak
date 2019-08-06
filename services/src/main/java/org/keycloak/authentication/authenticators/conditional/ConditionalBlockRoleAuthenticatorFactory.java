package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class ConditionalBlockRoleAuthenticatorFactory implements AuthenticatorFactory {
    private static final String PROVIDER_ID = "conditional-user-role";
    protected static final String CONDITIONAL_USER_ROLE = "condUserRole";

    @Override
    public Authenticator create(KeycloakSession session) {
        return ConditionalBlockRoleAuthenticator.SINGLETON;
    }

    @Override
    public void init(Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Conditional block - user role";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if user has the given role.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(new ProviderConfigProperty(
            CONDITIONAL_USER_ROLE, "User role", "Role the user should have to execute this flow", ProviderConfigProperty.STRING_TYPE, null
        ));
    }
}
