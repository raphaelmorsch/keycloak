package org.keycloak.testsuite.forms;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.broker.IdpAutoLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.PasswordFormFactory;
import org.keycloak.authentication.authenticators.browser.UsernameForm;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.resources.admin.AuthenticationManagementResource;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.ActionURIUtils;
import org.keycloak.testsuite.auth.page.login.OneTimeCode;
import org.keycloak.testsuite.model.ClientModelTest;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.LoginUsernameOnlyPage;
import org.keycloak.testsuite.pages.PasswordPage;
import org.keycloak.testsuite.runonserver.RunOnServer;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.URLUtils;
import org.keycloak.testsuite.util.WaitUtils;
import org.openqa.selenium.WebDriver;

import java.net.URI;
import java.util.List;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;
import static org.keycloak.testsuite.arquillian.DeploymentTargetModifier.AUTH_SERVER_CURRENT;

public class BrowserFlowTest extends AbstractTestRealmKeycloakTest {
    private static final String INVALID_AUTH_CODE = "Invalid authenticator code.";

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
    private OneTimeCode oneTimeCodePage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Deployment
    @TargetsContainer(AUTH_SERVER_CURRENT)
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class, ClientModelTest.class)
                .addPackages(true,
                        "org.keycloak.testsuite",
                        "org.keycloak.testsuite.model");
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        log.debug("Adding test realm for import from testrealm.json");
        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        testRealm.setBrowserFlow("browser");
        testRealms.add(testRealm);
    }

    private void provideUsernamePassword(String user) {
        // Go to login page
        loginPage.open();
        loginPage.assertCurrent();

        // Login attempt with an invalid password
        loginPage.login(user, "invalid");
        loginPage.assertCurrent();

        // Login attempt with a valid password - user with configured OTP
        loginPage.login(user, "password");
    }

    private String getOtpCode(String key) throws InterruptedException {
        return new TimeBasedOTP().generateTOTP(key);
    }

    @Test
    public void userWithoutAdditionalFactorConnection() {
        provideUsernamePassword("test-user@localhost");
        Assert.assertFalse(loginPage.isCurrent());
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void userWithOneAdditionalFactorOtpFails() {
        provideUsernamePassword("user-with-one-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());

        oneTimeCodePage.sendCode("123456");
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void userWithOneAdditionalFactorOtpSuccess() throws InterruptedException {
        provideUsernamePassword("user-with-one-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());

        oneTimeCodePage.sendCode(getOtpCode("DJmQfC73VGFhw7D4QJ8A"));
        Assert.assertFalse(loginPage.isCurrent());
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void userWithTwoAdditionalFactors() throws InterruptedException {
        final String firstKey = "DJmQfC73VGFhw7D4QJ8A";
        final String secondKey = "ABCQfC73VGFhw7D4QJ8A";

        // Provide username and password
        provideUsernamePassword("user-with-two-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());

        // Select "second" factor but try to connect with the OTP code from the "first" one
        oneTimeCodePage.selectFactor("second");
        oneTimeCodePage.sendCode(getOtpCode(firstKey));
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());

        // Select "first" factor but try to connect with the OTP code from the "second" one
        oneTimeCodePage.selectFactor("first");
        oneTimeCodePage.sendCode(getOtpCode(secondKey));
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());

        // Select "second" factor and try to connect with its OTP code
        oneTimeCodePage.selectFactor("second");
        oneTimeCodePage.sendCode(getOtpCode(secondKey));
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }


    @Test
    public void testSwitchExecutionNotAllowedWithRequiredPasswordAndAlternativeOTP() {
        testingClient.server("test").run(configureBrowserFlowWithRequiredPasswordFormAndAlternativeOTP("browser - copy 1"));

        try {
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.assertCurrent();
            loginUsernameOnlyPage.login("user-with-one-configured-otp");

            // Assert on password page now
            passwordPage.assertCurrent();

            String otpAuthenticatorExecutionId = realmsResouce().realm("test").flows().getExecutions("browser - copy 1")
                    .stream()
                    .filter(execution -> OTPFormAuthenticatorFactory.PROVIDER_ID.equals(execution.getProviderId()))
                    .findFirst()
                    .get()
                    .getId();

            // Manually run request to switch execution to OTP. It shouldn't be allowed and error should be thrown
            String actionURL = ActionURIUtils.getActionURIFromPageSource(driver.getPageSource());
            String formParameters = Constants.AUTHENTICATION_EXECUTION + "=" + otpAuthenticatorExecutionId + "&"
                    + Constants.CREDENTIAL_ID + "=";

            URLUtils.sendPOSTRequestWithWebDriver(actionURL, formParameters);

            errorPage.assertCurrent();

        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }


    // Configure the browser flow with those 3 authenticators at same level as subflows of the "Form":
    // UsernameForm: REQUIRED
    // PasswordForm: REQUIRED
    // OTPFormAuthenticator: ALTERNATIVE
    // In reality, the configuration of the flow like this doesn't have much sense, but nothing prevents administrator to configure it at this moment
    private static RunOnServer configureBrowserFlowWithRequiredPasswordFormAndAlternativeOTP(String newFlowAlias) {
        return (session -> {
            // Copy existing browser flow
            RealmModel appRealm = session.getContext().getRealm();
            AuthenticationFlowModel existingBrowserFlow = appRealm.getFlowByAlias(DefaultAuthenticationFlows.BROWSER_FLOW);

            AuthenticationFlowModel newBrowserFlow = AuthenticationManagementResource.copyFlow(appRealm, existingBrowserFlow, newFlowAlias);

            //
            AuthenticationFlowModel formSubflow = appRealm.getFlowByAlias(newFlowAlias + " forms");
            List<AuthenticationExecutionModel> executions = appRealm.getAuthenticationExecutions(formSubflow.getId());

            // Remove all executions
            for (AuthenticationExecutionModel authExecution : executions) {
                appRealm.removeAuthenticatorExecution(authExecution);
            }

            // Add REQUIRED UsernameForm Authenticator as first
            AuthenticationExecutionModel execution1 = new AuthenticationExecutionModel();
            execution1.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution1.setAuthenticatorFlow(false);
            execution1.setAuthenticator(UsernameFormFactory.PROVIDER_ID);
            execution1.setPriority(10);
            execution1.setParentFlow(formSubflow.getId());
            execution1 = appRealm.addAuthenticatorExecution(execution1);

            // Add REQUIRED PasswordForm Authenticator as second
            AuthenticationExecutionModel execution2 = new AuthenticationExecutionModel();
            execution2.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution2.setAuthenticatorFlow(false);
            execution2.setAuthenticator(PasswordFormFactory.PROVIDER_ID);
            execution2.setPriority(20);
            execution2.setParentFlow(formSubflow.getId());
            execution2 = appRealm.addAuthenticatorExecution(execution2);

            // Add ALTERNATIVE OTPFormAuthenticator as third
            AuthenticationExecutionModel execution3 = new AuthenticationExecutionModel();
            execution3.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
            execution3.setAuthenticatorFlow(false);
            execution3.setAuthenticator(OTPFormAuthenticatorFactory.PROVIDER_ID);
            execution3.setPriority(30);
            execution3.setParentFlow(formSubflow.getId());
            execution3 = appRealm.addAuthenticatorExecution(execution3);

            // Add OTPForm ALTERNATIVE execution
            appRealm.setBrowserFlow(newBrowserFlow);
        });
    }


    private static RunOnServer setBrowserFlowToRealm() {
        return (session -> {
            RealmModel appRealm = session.getContext().getRealm();
            AuthenticationFlowModel existingBrowserFlow = appRealm.getFlowByAlias(DefaultAuthenticationFlows.BROWSER_FLOW);
            appRealm.setBrowserFlow(existingBrowserFlow);
        });
    }
}
