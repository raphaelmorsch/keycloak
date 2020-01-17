/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
 */

package org.keycloak.authentication;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ConfiguredProvider;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ConfigurableAuthenticatorFactory extends ConfiguredProvider {

    AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED};

    /**
     * Friendly name for the authenticator
     *
     * @return
     */
    String getDisplayType();

    /**
     * General authenticator type, i.e. totp, password, cert.
     *
     * @return null if not a referencable category
     */
    String getReferenceCategory();

    /**
     * Is this authenticator configurable?
     *
     * @return
     */
    boolean isConfigurable();

    /**
     * What requirement settings are allowed.
     *
     * @return
     */
    AuthenticationExecutionModel.Requirement[] getRequirementChoices();

    /**
     *
     * Does this authenticator have required actions that can set if the user does not have
     * this authenticator set up?
     *
     *
     * @return
     */
    boolean isUserSetupAllowed();

    /**
     * Returns the label, which will be shown to the end user on various screens, like login screen with available authentication mechanisms.
     * This label will reference this particular authenticator type.
     * It should be clear to end users. For example, implementations can return "Authenticator Application" for OTP or "Security Key" for WebAuthn.
     *
     * Alternatively, this method can return a message key, so that it is possible to localize it for various languages.
     *
     * Authenticators, which don't require user interactions may typically just fallback to {@link #getDisplayType()}
     */
    default String getUserDisplayName() {
        return getDisplayType();
    }

    /**
     * Returns the text, which will be shown to the user on various screens, like login screen with available authentication mechanisms.
     * This text will reference this particular authenticator type.
     * For example for OTP, the returned text could be "Enter a verification code from authenticator application" .
     *
     * Alternatively, this method can return a message key, so that it is possible to localize it for various languages.
     *
     * The difference to {@link #getHelpText()} method is, that this method is shown to end users, not to the administrators.
     * Authenticators, which don't require user interactions may typically just fallback to {@link #getHelpText()}.
     */
    default String getUserHelpText() {
        return getHelpText();
    }


    /**
     * Return the icon CSS, which can be used to display icon, which represents this particular authenticator.
     *
     * The icon will be displayed on various places. For example the "Select authenticator" screen during login, where user can select from
     * various authentication mechanisms for two-factor or passwordless authentication.
     *
     * The returned value can be either:
     * - Key of the property, which will reference the actual CSS in the themes.properties file. For example if you return "kcAuthenticatorWebAuthnClass"
     *   from this method, then your themes.properties should have the property like for example "kcAuthenticatorWebAuthnClass=fa fa-key list-view-pf-icon-lg" .
     *   This would mean that "fa fa-key list-view-pf-icon-lg" will be the actual CSS used.
     * - the icon CSS class directly. For example you can return "fa fa-key list-view-pf-icon-lg" directly for the above example with WebAuthn.
     *   This alternative is fine just if your authenticator can use same CSS class for all the themes.
     *
     * If you don't expect your authenticator to need icon (for example it will never be shown in the "select authenticator" screen), then
     * it is fine to keep the default value.
     */
    default String getIconCssClass() {
        return "kcAuthenticatorDefaultClass";
    }
}
