/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.authentication.authenticators.browser;

import java.util.Collections;
import java.util.List;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnStrongRegisterFactory;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.credential.WebAuthnStrongCredentialProvider;
import org.keycloak.credential.WebAuthnStrongCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * Authenticator for WebAuthn authentication with strong (passwordless) credential. This class is temporary and will be likely
 * removed in the future during future improvements in authentication SPI
 */
public class WebAuthnStrongAuthenticator extends WebAuthnAuthenticator {

    public WebAuthnStrongAuthenticator(KeycloakSession session) {
        super(session);
    }

    @Override
    protected WebAuthnPolicy getWebAuthnPolicy(AuthenticationFlowContext context) {
        return context.getRealm().getWebAuthnPolicyStrong();
    }

    @Override
    protected String getCredentialType() {
        return WebAuthnCredentialModel.TYPE_STRONG;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // ask the user to do required action to register webauthn authenticator
        if (!user.getRequiredActions().contains(WebAuthnStrongRegisterFactory.PROVIDER_ID)) {
            user.addRequiredAction(WebAuthnStrongRegisterFactory.PROVIDER_ID);
        }
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((WebAuthnStrongRegisterFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, WebAuthnStrongRegisterFactory.PROVIDER_ID));
    }


    @Override
    public WebAuthnStrongCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (WebAuthnStrongCredentialProvider)session.getProvider(CredentialProvider.class, WebAuthnStrongCredentialProviderFactory.PROVIDER_ID);
    }

}
