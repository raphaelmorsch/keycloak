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
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.auth.page.login.OneTimeCode;
import org.keycloak.testsuite.model.ClientModelTest;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.OAuthClient;
import org.openqa.selenium.WebDriver;

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
        long timeBeforeNextOtpCodeInMillis = 30000L - (System.currentTimeMillis() % 30000);
        if (timeBeforeNextOtpCodeInMillis < 2000) {
            Thread.sleep(timeBeforeNextOtpCodeInMillis);
        }
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
}
