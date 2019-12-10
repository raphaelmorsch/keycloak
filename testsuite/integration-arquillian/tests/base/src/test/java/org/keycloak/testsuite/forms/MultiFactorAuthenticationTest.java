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

package org.keycloak.testsuite.forms;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.PasswordFormFactory;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.client.KeycloakTestingClient;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.LoginTotpPage;
import org.keycloak.testsuite.pages.LoginUsernameOnlyPage;
import org.keycloak.testsuite.pages.PasswordPage;
import org.keycloak.testsuite.pages.SelectAuthenticatorPage;
import org.keycloak.testsuite.util.FlowUtil;
import org.keycloak.testsuite.util.OAuthClient;
import org.openqa.selenium.WebDriver;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * Test various scenarios for multi-factor login. Test that "Try another way" link works as expected
 * and users are able to choose between various alternative authenticators for the particular factor (1st factor, 2nd factor)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class MultiFactorAuthenticationTest extends AbstractTestRealmKeycloakTest {

    @ArquillianResource
    protected OAuthClient oauth;

    @Drone
    protected WebDriver driver;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginUsernameOnlyPage loginUsernameOnlyPage;

    @Page
    protected PasswordPage passwordPage;

    @Page
    protected ErrorPage errorPage;

    @Page
    protected LoginTotpPage loginTotpPage;

    @Page
    protected SelectAuthenticatorPage selectAuthenticatorPage;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    private RealmRepresentation loadTestRealm() {
        RealmRepresentation res = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        res.setBrowserFlow("browser");
        return res;
    }

    private void importTestRealm(Consumer<RealmRepresentation> realmUpdater) {
        RealmRepresentation realm = loadTestRealm();
        if (realmUpdater != null) {
            realmUpdater.accept(realm);
        }
        importRealm(realm);
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        log.debug("Adding test realm for import from testrealm.json");
        testRealms.add(loadTestRealm());
    }


    // In a sub-flow with alternative credential executors, check which credentials are available and in which order
    // This also tests "try another way" link
    @Test
    public void testAlternativeCredentials() {
        try {
            configureBrowserFlowWithAlternativeCredentials();

            // test-user has not other credential than his password. No try-another-way link is displayed
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("test-user@localhost");
            passwordPage.assertCurrent();
            loginTotpPage.assertTryAnotherWayLinkAvailability(false);

            // A user with only one other credential than his password: the try-another-way link should be accessible
            // and he should be able to choose between his password and his OTP credentials
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-one-configured-otp");
            passwordPage.assertCurrent();
            passwordPage.assertTryAnotherWayLinkAvailability(true);
            passwordPage.clickTryAnotherWayLink();

            selectAuthenticatorPage.assertCurrent();
            Assert.assertEquals(Arrays.asList("Password", "OTP"), selectAuthenticatorPage.getAvailableLoginMethods());

            // Select OTP and see that just single OTP is available for this user
            selectAuthenticatorPage.selectLoginMethod("OTP");
            loginTotpPage.assertCurrent();
            loginTotpPage.assertTryAnotherWayLinkAvailability(true);
            loginTotpPage.assertOtpCredentialSelectorAvailability(false);

            // A user with two OTP credentials and password credential: He should be able to choose just between the password and OTP similarly
            // like user with user-with-one-configured-otp. However OTP is preferred credential for him, so OTP mechanism will take preference
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-two-configured-otp");
            loginTotpPage.assertCurrent();
            loginTotpPage.assertTryAnotherWayLinkAvailability(true);

            // More OTP credentials should be available for this user
            loginTotpPage.assertOtpCredentialSelectorAvailability(true);

            loginTotpPage.clickTryAnotherWayLink();

            selectAuthenticatorPage.assertCurrent();
            Assert.assertEquals(Arrays.asList("OTP", "Password"), selectAuthenticatorPage.getAvailableLoginMethods());
        } finally {
            BrowserFlowTest.revertFlows(testRealm(), "browser - alternative");
        }
    }

    private void configureBrowserFlowWithAlternativeCredentials() {
        configureBrowserFlowWithAlternativeCredentials(testingClient);
    }

    static void configureBrowserFlowWithAlternativeCredentials(KeycloakTestingClient testingClient) {
        final String newFlowAlias = "browser - alternative";
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyBrowserFlow(newFlowAlias));
        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session)
                .selectFlow(newFlowAlias)
                .inForms(forms -> forms
                        .clear()
                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                        .addSubFlowExecution(AuthenticationExecutionModel.Requirement.REQUIRED, altSubFlow -> altSubFlow
                                // Add 2 basic authenticator executions
                                .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, PasswordFormFactory.PROVIDER_ID)
                                .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, OTPFormAuthenticatorFactory.PROVIDER_ID)
                        )
                )
                .defineAsBrowserFlow()
        );
    }


    // TODO:mposolda - test with alternatives at different subflow
//    @Test
//    public void testBackButtonFromAlternativeSubflow() {
//        final String newFlowAlias = "browser - back button subflow";
//        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session).copyBrowserFlow(newFlowAlias));
//        testingClient.server("test").run(session -> FlowUtil.inCurrentRealm(session)
//                .selectFlow(newFlowAlias)
//                .inForms(forms -> forms
//                        .clear()
//                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
//                        .addSubFlowExecution(Requirement.REQUIRED, reqSubFlow -> reqSubFlow
//                                // Add authenticators to this flow: 1 PASSWORD, 2 Another subflow with having only OTP as child
//                                .addAuthenticatorExecution(Requirement.ALTERNATIVE, PasswordFormFactory.PROVIDER_ID)
//                                .addSubFlowExecution("otp subflow", AuthenticationFlow.BASIC_FLOW, Requirement.ALTERNATIVE, altSubFlow -> altSubFlow
//                                        .addAuthenticatorExecution(Requirement.REQUIRED, OTPFormAuthenticatorFactory.PROVIDER_ID)
//                                )
//                        )
//                )
//                .defineAsBrowserFlow()
//        );
//
//        try {
//            // Provide username, should be on password page
//            needsPassword("user-with-one-configured-otp");
//
//            // Select the OTP subflow. The credential selection won't be on the page due it's subflow
//            passwordPage.selectCredential("otp subflow");
//            loginTotpPage.assertCurrent();
//            loginTotpPage.assertCredentialsComboboxAvailability(false);
//
//            // Click "back". Should be on password page
//            loginTotpPage.clickBackButton();
//            passwordPage.assertCurrent();
//            passwordPage.login("password");
//
//            Assert.assertFalse(passwordPage.isCurrent());
//            Assert.assertFalse(loginPage.isCurrent());
//            events.expectLogin().user(testRealm().users().search("user-with-one-configured-otp").get(0).getId())
//                    .detail(Details.USERNAME, "user-with-one-configured-otp").assertEvent();
//        } finally {
//            revertFlows("browser - back button subflow");
//        }
//    }
}
