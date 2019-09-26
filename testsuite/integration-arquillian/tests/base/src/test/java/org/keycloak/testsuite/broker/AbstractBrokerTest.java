package org.keycloak.testsuite.broker;

import org.junit.Test;

import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.pages.ConsentPage;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.keycloak.models.utils.DefaultAuthenticationFlows.IDP_REVIEW_PROFILE_CONFIG_ALIAS;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

import org.jboss.arquillian.graphene.page.Page;

import javax.ws.rs.core.Response;

/**
 * Contains just few basic tests. This is good class to override if you're testing custom IDP configuration and you need
 * to verify if login with IDP works as expected
 */
public abstract class AbstractBrokerTest extends AbstractInitializedBaseBrokerTest {

    public static final String ROLE_USER = "user";
    public static final String ROLE_MANAGER = "manager";
    public static final String ROLE_FRIENDLY_MANAGER = "friendly-manager";
    public static final String ROLE_USER_DOT_GUIDE = "user.guide";

    @Page
    ConsentPage consentPage;

    @Test
    public void testLogInAsUserInIDP() {
        loginUser();

        testSingleLogout();
    }

    protected void loginUser() {
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        logInWithBroker(bc);

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
          driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));

        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserLogin(), bc.getUserEmail(), "Firstname", "Lastname");

        UsersResource consumerUsers = adminClient.realm(bc.consumerRealmName()).users();

        int userCount = consumerUsers.count();
        Assert.assertTrue("There must be at least one user", userCount > 0);

        List<UserRepresentation> users = consumerUsers.search("", 0, userCount);

        boolean isUserFound = false;
        for (UserRepresentation user : users) {
            if (user.getUsername().equals(bc.getUserLogin()) && user.getEmail().equals(bc.getUserEmail())) {
                isUserFound = true;
                break;
            }
        }

        Assert.assertTrue("There must be user " + bc.getUserLogin() + " in realm " + bc.consumerRealmName(),
          isUserFound);
    }


    @Test
    public void loginWithExistingUser() {
        testLogInAsUserInIDP();

        Integer userCount = adminClient.realm(bc.consumerRealmName()).users().count();

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        assertEquals(accountPage.buildUri().toASCIIString().replace("master", "consumer") + "/", driver.getCurrentUrl());
        assertEquals(userCount, adminClient.realm(bc.consumerRealmName()).users().count());
    }

<<<<<<< HEAD
=======
    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest#testSuccessfulAuthenticationWithoutUpdateProfile_emailProvided_emailVerifyEnabled
     */
    @Test
    public void testLinkAccountWithUntrustedEmailVerified() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        RealmRepresentation realmRep = realm.toRepresentation();

        realmRep.setVerifyEmail(true);

        realm.update(realmRep);

        IdentityProviderRepresentation idpRep = identityProviderResource.toRepresentation();

        idpRep.setTrustEmail(false);

        identityProviderResource.update(idpRep);

        configureSMTPServer();

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");

        verifyEmailPage.assertCurrent();

        String verificationUrl = assertEmailAndGetUrl(MailServerConfiguration.FROM, USER_EMAIL,
                "verify your email address", false);

        driver.navigate().to(verificationUrl.trim());
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest#testSuccessfulAuthenticationWithoutUpdateProfile_emailNotProvided_emailVerifyEnabled
     */
    @Test
    public void testVerifyEmailRequiredActionWhenEmailIsNotVerifiedDuringFirstLogin() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        RealmRepresentation realmRep = realm.toRepresentation();

        realmRep.setVerifyEmail(true);

        realm.update(realmRep);

        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);
        createUser(bc.providerRealmName(), "no-email", "password", "FirstName", "LastName", null);

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login("no-email", "password");

        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        List<UserRepresentation> users = realm.users().search("no-email");
        assertEquals(1, users.size());
        List<String> requiredActions = users.get(0).getRequiredActions();
        assertEquals(1, requiredActions.size());
        assertEquals(UserModel.RequiredAction.VERIFY_EMAIL.name(), requiredActions.get(0));

    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest#testSuccessfulAuthenticationWithoutUpdateProfile_emailProvided_emailVerifyEnabled_emailTrustEnabled
     */
    @Test
    public void testVerifyEmailNotRequiredActionWhenEmailIsTrustedByProvider() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        RealmRepresentation realmRep = realm.toRepresentation();

        realmRep.setVerifyEmail(true);

        realm.update(realmRep);

        IdentityProviderRepresentation idpRep = identityProviderResource.toRepresentation();

        idpRep.setTrustEmail(true);

        identityProviderResource.update(idpRep);

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");

        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        List<UserRepresentation> users = realm.users().search(bc.getUserLogin());
        assertEquals(1, users.size());
        List<String> requiredActions = users.get(0).getRequiredActions();
        assertEquals(0, requiredActions.size());
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest#testSuccessfulAuthentication_emailTrustEnabled_emailVerifyEnabled_emailUpdatedOnFirstLogin
     */
    @Test
    public void testVerifyEmailRequiredActionWhenChangingEmailDuringFirstLogin() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        RealmRepresentation realmRep = realm.toRepresentation();

        realmRep.setVerifyEmail(true);

        realm.update(realmRep);

        IdentityProviderRepresentation idpRep = identityProviderResource.toRepresentation();

        idpRep.setTrustEmail(true);

        identityProviderResource.update(idpRep);

        configureSMTPServer();

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("changed@localhost.com", "FirstName", "LastName");

        verifyEmailPage.assertCurrent();

        String verificationUrl = assertEmailAndGetUrl(MailServerConfiguration.FROM, "changed@localhost.com",
                "verify your email address", false);

        driver.navigate().to(verificationUrl.trim());
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        List<UserRepresentation> users = realm.users().search(bc.getUserLogin());
        assertEquals(1, users.size());
        List<String> requiredActions = users.get(0).getRequiredActions();
        assertEquals(0, requiredActions.size());
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractFirstBrokerLoginTest#testLinkAccountByEmailVerificationTwice
     */
    @Test
    public void testLinkAccountByEmailVerificationTwice() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());

        UserResource userResource = realm.users().get(createUser("consumer"));
        UserRepresentation consumerUser = userResource.toRepresentation();

        consumerUser.setEmail(bc.getUserEmail());
        userResource.update(consumerUser);
        configureSMTPServer();

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        //link account by email
        waitForPage(driver, "update account information", false);
        Assert.assertTrue(updateAccountInformationPage.isCurrent());
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");
        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        assertEquals("User with email user@localhost.com already exists. How do you want to continue?", idpConfirmLinkPage.getMessage());
        idpConfirmLinkPage.clickLinkAccount();

        String url = assertEmailAndGetUrl(MailServerConfiguration.FROM, USER_EMAIL,
                "Someone wants to link your ", false);
        driver.navigate().to(url);
        //test if user is logged in
        assertEquals(accountPage.buildUri().toASCIIString().replace("master", "consumer") + "/", driver.getCurrentUrl());
        //test if the user has verified email
        assertTrue(adminClient.realm(bc.consumerRealmName()).users().get(consumerUser.getId()).toRepresentation().isEmailVerified());

        driver.navigate().to(url);
        waitForPage(driver, "you are already logged in.", false);
        logoutFromRealm(bc.consumerRealmName());

        driver.navigate().to(url);
        waitForPage(driver, "confirm linking the account testuser of identity provider " + bc.getIDPAlias() + " with your account.", false);
        proceedPage.clickProceedLink();
        waitForPage(driver, "you successfully verified your email. please go back to your original browser and continue there with the login.", false);
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractFirstBrokerLoginTest#testLinkAccountByEmailVerificationResendEmail
     */
    @Test
    public void testLinkAccountByEmailVerificationResendEmail() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());

        UserResource userResource = realm.users().get(createUser("consumer"));
        UserRepresentation consumerUser = userResource.toRepresentation();

        consumerUser.setEmail(bc.getUserEmail());
        userResource.update(consumerUser);
        configureSMTPServer();

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        //link account by email
        waitForPage(driver, "update account information", false);
        Assert.assertTrue(updateAccountInformationPage.isCurrent());
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");
        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        assertEquals("User with email user@localhost.com already exists. How do you want to continue?", idpConfirmLinkPage.getMessage());
        idpConfirmLinkPage.clickLinkAccount();


        waitForPage(driver, "link " + bc.getIDPAlias(), false);
        assertEquals("an email with instructions to link " + bc.getIDPAlias() + " account testuser with your consumer account has been sent to you.", idpLinkEmailPage.getMessage().toLowerCase());
        idpLinkEmailPage.resendEmail();

        assertEquals(2, MailServer.getReceivedMessages().length);
    }

    @Test
    public void testVerifyEmailInNewBrowserWithPreserveClient() {
        RealmResource consumerRealm = adminClient.realm(bc.consumerRealmName());

        configureSMTPServer();

        //create user on consumer's site who should be linked later
        String linkedUserId = createUser("consumer");

        driver.navigate().to(getLoginUrl(bc.consumerRealmName(), "broker-app"));
        logInWithBroker(bc);

        waitForPage(driver, "update account information", false);

        Assert.assertTrue(updateAccountInformationPage.isCurrent());
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));

        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation("Firstname", "Lastname");

        //link account by email
        waitForPage(driver, "account already exists", false);
        idpConfirmLinkPage.clickLinkAccount();

        String url = assertEmailAndGetUrl(MailServerConfiguration.FROM, USER_EMAIL,
                "Someone wants to link your ", false);

        log.info("navigating to url from email in second browser: " + url);

        // navigate to url in the second browser
        driver2.navigate().to(url);

        final WebElement proceedLink = driver2.findElement(By.linkText("» Click here to proceed"));
        MatcherAssert.assertThat(proceedLink, Matchers.notNullValue());

        // check if the initial client is preserved
        String link = proceedLink.getAttribute("href");
        MatcherAssert.assertThat(link, Matchers.containsString("client_id=broker-app"));
        proceedLink.click();

        assertThat(driver2.getPageSource(), Matchers.containsString("You successfully verified your email. Please go back to your original browser and continue there with the login."));

        //test if the user has verified email
        assertTrue(consumerRealm.users().get(linkedUserId).toRepresentation().isEmailVerified());
    }

    // KEYCLOAK-3267
    @Test
    public void loginWithExistingUserWithBruteForceEnabled() {
        adminClient.realm(bc.consumerRealmName()).update(RealmBuilder.create().bruteForceProtected(true).failureFactor(2).build());

        loginWithExistingUser();

        driver.navigate().to(getAccountPasswordUrl(bc.consumerRealmName()));

        accountPasswordPage.changePassword("password", "password");

        logoutFromRealm(bc.providerRealmName());

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        try {
            waitForPage(driver, "log in to", true);
        } catch (TimeoutException e) {
            log.debug(driver.getTitle());
            log.debug(driver.getPageSource());
            Assert.fail("Timeout while waiting for login page");
        }

        for (int i = 0; i < 3; i++) {
            try {
                waitForElementEnabled(driver, "login");
            } catch (TimeoutException e) {
                Assert.fail("Timeout while waiting for login element enabled");
            }

            accountLoginPage.login(bc.getUserLogin(), "invalid");
        }

        assertEquals("Invalid username or password.", accountLoginPage.getError());

        accountLoginPage.clickSocial(bc.getIDPAlias());

        try {
            waitForPage(driver, "log in to", true);
        } catch (TimeoutException e) {
            log.debug(driver.getTitle());
            log.debug(driver.getPageSource());
            Assert.fail("Timeout while waiting for login page");
        }

        Assert.assertTrue("Driver should be on the provider realm page right now", driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));

        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());

        assertEquals("Account is disabled, contact admin.", errorPage.getError());
    }

    // KEYCLOAK-4181
    @Test
    public void loginWithExistingUserWithErrorFromProviderIdP() {
        ClientRepresentation client = adminClient.realm(bc.providerRealmName())
          .clients()
          .findByClientId(bc.getIDPClientIdInProviderRealm(suiteContext))
          .get(0);

        adminClient.realm(bc.providerRealmName())
          .clients()
          .get(client.getId())
          .update(ClientBuilder.edit(client).consentRequired(true).build());

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);

        driver.manage().timeouts().pageLoadTimeout(30, TimeUnit.MINUTES);

        waitForPage(driver, "grant access", false);
        consentPage.cancel();

        waitForPage(driver, "log in to", true);

        // Revert consentRequired
        adminClient.realm(bc.providerRealmName())
                .clients()
                .get(client.getId())
                .update(ClientBuilder.edit(client).consentRequired(false).build());

    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest.testDisabledUser
     */
    @Test
    public void testDisabledUser() {
        loginUser();
        logoutFromRealm(bc.providerRealmName());
        logoutFromRealm(bc.consumerRealmName());

        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        UserRepresentation userRep = realm.users().search(bc.getUserLogin()).get(0);
        UserResource user = realm.users().get(userRep.getId());

        userRep.setEnabled(false);

        user.update(userRep);

        logInWithBroker(bc);
        errorPage.assertCurrent();
        assertEquals("Account is disabled, contact admin.", errorPage.getError());
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest.testSuccessfulAuthenticationUpdateProfileOnMissing_missingEmail
     */
    @Test
    public void testUpdateProfileIfMissingInformation() {
        updateExecutions(AbstractBrokerTest::setUpMissingUpdateProfileOnFirstLogin);

        createUser(bc.providerRealmName(), "no-first-name", "password", null, "LastName", "no-first-name@localhost.com");
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login("no-first-name", "password");

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        logoutFromRealm(bc.providerRealmName());
        logoutFromRealm(bc.consumerRealmName());
        createUser(bc.providerRealmName(), "no-last-name", "password", "FirstName", null, "no-last-name@localhost.com");
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login("no-last-name", "password");

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        logoutFromRealm(bc.providerRealmName());
        logoutFromRealm(bc.consumerRealmName());
        createUser(bc.providerRealmName(), "no-email", "password", "FirstName", "LastName", null);
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login("no-email", "password");

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.updateAccountInformation("no-email@localhost.com", "FirstName", "LastName");

        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest.testSuccessfulAuthenticationUpdateProfileOnMissing_nothingMissing
     */
    @Test
    public void testUpdateProfileIfNotMissingInformation() {
        updateExecutions(AbstractBrokerTest::setUpMissingUpdateProfileOnFirstLogin);
        createUser(bc.providerRealmName(), "all-info-set", "password", "FirstName", "LastName", "all-info-set@localhost.com");

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login("all-info-set", "password");

        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest.testSuccessfulAuthenticationWithoutUpdateProfile
     */
    @Test
    public void testWithoutUpdateProfile() {
        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        logInWithBroker(bc);
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
    }


    // TODO:mposolda after rebase with latest master, this test should be moved to AbstractFirstBrokerLoginTest
    @Test
    public void testFormBackButton() {
        updateExecutions(AbstractBrokerTest::setUpMissingUpdateProfileOnFirstLogin);

        String existingUser = createUser("consumer");

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();

        // Assert "back" button not available
        updateAccountInformationPage.assertBackButtonAvailability(false);

        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");

        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        assertEquals("User with email user@localhost.com already exists. How do you want to continue?", idpConfirmLinkPage.getMessage());

        // Assert "back" button available. Click it.
        idpConfirmLinkPage.assertBackButtonAvailability(true);
        idpConfirmLinkPage.clickBackButton();

        // Assert on "update profile" page. "Back" button shouldn't still be available
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.assertBackButtonAvailability(false);

        // Update profile and click "Confirm link"
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");

        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        idpConfirmLinkPage.clickLinkAccount();

        assertEquals("Authenticate as consumer to link your account with " + bc.getIDPAlias(), loginPage.feedbackMessage().getText());
        accountLoginPage.assertBackButtonAvailability(true);

        // Click "Back" button two times. Should be on "Review profile" page
        accountLoginPage.clickBackButton();
        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        idpConfirmLinkPage.assertBackButtonAvailability(true);
        idpConfirmLinkPage.clickBackButton();

        // Assert on "update profile" page. "Back" button shouldn't still be available
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        updateAccountInformationPage.assertBackButtonAvailability(false);

        // Finally authenticate
        updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");

        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        idpConfirmLinkPage.clickLinkAccount();

        accountLoginPage.login("password");
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();

        assertNumFederatedIdentities(existingUser, 1);
    }


    // KEYCLOAK-3987
    @Test
    public void grantNewRoleFromToken() {
        createRolesForRealm(bc.providerRealmName());
        createRolesForRealm(bc.consumerRealmName());

        createRoleMappersForConsumerRealm();

        RoleRepresentation managerRole = adminClient.realm(bc.providerRealmName()).roles().get(ROLE_MANAGER).toRepresentation();
        RoleRepresentation userRole = adminClient.realm(bc.providerRealmName()).roles().get(ROLE_USER).toRepresentation();

        UserResource userResource = adminClient.realm(bc.providerRealmName()).users().get(userId);
        userResource.roles().realmLevel().add(Collections.singletonList(managerRole));

        logInAsUserInIDPForFirstTime();

        Set<String> currentRoles = userResource.roles().realmLevel().listAll().stream()
          .map(RoleRepresentation::getName)
          .collect(Collectors.toSet());

        assertThat(currentRoles, hasItems(ROLE_MANAGER));
        assertThat(currentRoles, not(hasItems(ROLE_USER)));

        logoutFromRealm(bc.consumerRealmName());


        userResource.roles().realmLevel().add(Collections.singletonList(userRole));

        logInAsUserInIDP();

        currentRoles = userResource.roles().realmLevel().listAll().stream()
          .map(RoleRepresentation::getName)
          .collect(Collectors.toSet());
        assertThat(currentRoles, hasItems(ROLE_MANAGER, ROLE_USER));

        logoutFromRealm(bc.providerRealmName());
        logoutFromRealm(bc.consumerRealmName());
    }


    // KEYCLOAK-4016
    @Test
    public void testExpiredCode() {
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        log.debug("Expire all browser cookies");
        driver.manage().deleteAllCookies();

        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());

        waitForPage(driver, "sorry", false);
        errorPage.assertCurrent();
        String link = errorPage.getBackToApplicationLink();
        Assert.assertTrue(link.endsWith("/auth/realms/consumer/account"));
    }

    /**
     * Refers to in old testsuite: org.keycloak.testsuite.broker.PostBrokerFlowTest#testPostBrokerLoginWithOTP()
     */
    @Test
    public void testPostBrokerLoginFlowWithOTP() {
        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);
        testingClient.server(bc.consumerRealmName()).run(configurePostBrokerLoginWithOTP(bc.getIDPAlias()));

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());

        totpPage.assertCurrent();
        String totpSecret = totpPage.getTotpSecret();
        totpPage.configure(totp.generateTOTP(totpSecret));
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        assertNumFederatedIdentities(realm.users().search(bc.getUserLogin()).get(0).getId(), 1);
        logoutFromRealm(bc.consumerRealmName());

        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());

        loginTotpPage.assertCurrent();
        loginTotpPage.login(totp.generateTOTP(totpSecret));
        logoutFromRealm(bc.consumerRealmName());

        testingClient.server(bc.consumerRealmName()).run(disablePostBrokerLoginFlow(bc.getIDPAlias()));
        log.debug("Clicking social " + bc.getIDPAlias());
        accountLoginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "log in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        log.debug("Logging in");
        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
    }

    /**
     * Refers to in old testsuite: org.keycloak.testsuite.broker.OIDCKeyCloakServerBrokerBasicTest#testLogoutWorksWithTokenTimeout()
     */
    @Test
    public void testLogoutWorksWithTokenTimeout() {
        try {
            updateExecutions(AbstractBrokerTest::enableUpdateProfileOnFirstLogin);
            RealmRepresentation realm = adminClient.realm(bc.providerRealmName()).toRepresentation();
            assertNotNull(realm);
            realm.setAccessTokenLifespan(1);
            adminClient.realm(bc.providerRealmName()).update(realm);
            IdentityProviderRepresentation idp = adminClient.realm(bc.consumerRealmName()).identityProviders().get(bc.getIDPAlias()).toRepresentation();
            idp.getConfig().put("backchannelSupported", "false");
            adminClient.realm(bc.consumerRealmName()).identityProviders().get(bc.getIDPAlias()).update(idp);
            Time.setOffset(2);
            driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
            logInWithBroker(bc);
            waitForPage(driver, "update account information", false);
            updateAccountInformationPage.assertCurrent();
            updateAccountInformationPage.updateAccountInformation("FirstName", "LastName");
            accountPage.logOut();
            waitForPage(driver, "log in to", true);
            log.debug("Logging in");
            assertTrue(this.driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/protocol/openid-connect/auth"));
        } finally {
            Time.setOffset(0);
        }
    }

    /**
     * Refers to in old test suite: org.keycloak.testsuite.broker.AbstractKeycloakIdentityProviderTest#testWithLinkedFederationProvider
     */
    @Test
    public void testWithLinkedFederationProvider() {
        try {
            updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);

            ComponentRepresentation component = new ComponentRepresentation();

            component.setId(DummyUserFederationProviderFactory.PROVIDER_NAME);
            component.setName(DummyUserFederationProviderFactory.PROVIDER_NAME);
            component.setProviderId(DummyUserFederationProviderFactory.PROVIDER_NAME);
            component.setProviderType(UserStorageProvider.class.getName());

            adminClient.realm(bc.consumerRealmName()).components().add(component);

            createUser(bc.providerRealmName(), "test-user", "password", "FirstName", "LastName", "test-user@localhost.com");
            driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
            accountLoginPage.clickSocial(bc.getIDPAlias());
            accountLoginPage.login("test-user", "password");
            waitForPage(driver, "keycloak account management", true);
            accountUpdateProfilePage.assertCurrent();

            accountPage.password();
            accountPasswordPage.changePassword("bad", "new-password", "new-password");
            assertEquals("Invalid existing password.", accountPasswordPage.getError());

            accountPasswordPage.changePassword("secret", "new-password", "new-password");
            assertEquals("Your password has been updated.", accountUpdateProfilePage.getSuccess());

            logoutFromRealm(bc.providerRealmName());
            logoutFromRealm(bc.consumerRealmName());

            createUser(bc.providerRealmName(), "test-user-noemail", "password", "FirstName", "LastName", "test-user-noemail@localhost.com");
            driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
            accountLoginPage.clickSocial(bc.getIDPAlias());
            accountLoginPage.login("test-user-noemail", "password");
            waitForPage(driver, "keycloak account management", true);
            accountUpdateProfilePage.assertCurrent();

            accountPage.password();
            accountPasswordPage.changePassword("new-password", "new-password");
            assertEquals("Your password has been updated.", accountUpdateProfilePage.getSuccess());
        } finally {
            removeUserByUsername(adminClient.realm(bc.consumerRealmName()), "test-user");
            removeUserByUsername(adminClient.realm(bc.consumerRealmName()), "test-user-noemail");
        }
    }
>>>>>>> c7232e6947... Cherry- pick 2r

    protected void testSingleLogout() {
        log.debug("Testing single log out");

        driver.navigate().to(getAccountUrl(bc.providerRealmName()));

        Assert.assertTrue("Should be logged in the account page", driver.getTitle().endsWith("Account Management"));

        logoutFromRealm(bc.providerRealmName());

        Assert.assertTrue("Should be on " + bc.providerRealmName() + " realm", driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName()));

        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        Assert.assertTrue("Should be on " + bc.consumerRealmName() + " realm on login page",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/protocol/openid-connect/"));
    }

    protected void createRolesForRealm(String realm) {
        RoleRepresentation managerRole = new RoleRepresentation(ROLE_MANAGER,null, false);
        RoleRepresentation friendlyManagerRole = new RoleRepresentation(ROLE_FRIENDLY_MANAGER,null, false);
        RoleRepresentation userRole = new RoleRepresentation(ROLE_USER,null, false);
        RoleRepresentation userGuideRole = new RoleRepresentation(ROLE_USER_DOT_GUIDE,null, false);

        adminClient.realm(realm).roles().create(managerRole);
        adminClient.realm(realm).roles().create(friendlyManagerRole);
        adminClient.realm(realm).roles().create(userRole);
        adminClient.realm(realm).roles().create(userGuideRole);
    }

    static void enableUpdateProfileOnFirstLogin(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {
        if (execution.getProviderId() != null && execution.getProviderId().equals(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID)) {
            execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.name());
            flows.updateExecutions(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW, execution);
        } else if (execution.getAlias() != null && execution.getAlias().equals(IDP_REVIEW_PROFILE_CONFIG_ALIAS)) {
            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            config.getConfig().put("update.profile.on.first.login", IdentityProviderRepresentation.UPFLM_ON);
            flows.updateAuthenticatorConfig(config.getId(), config);
        }
    }

    static void setUpMissingUpdateProfileOnFirstLogin(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {
        if (execution.getProviderId() != null && execution.getProviderId().equals(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID)) {
            execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE.name());
            flows.updateExecutions(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW, execution);
        } else if (execution.getAlias() != null && execution.getAlias().equals(IDP_REVIEW_PROFILE_CONFIG_ALIAS)) {
            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            config.getConfig().put("update.profile.on.first.login", IdentityProviderRepresentation.UPFLM_MISSING);
            flows.updateAuthenticatorConfig(config.getId(), config);
        }
    }

    static void enableRequirePassword(AuthenticationExecutionInfoRepresentation execution,
            AuthenticationManagementResource flows) {
        String id = execution.getAuthenticationConfig();

        if (id != null) {
            AuthenticatorConfigRepresentation authenticatorConfig = flows.getAuthenticatorConfig(id);

            if (authenticatorConfig != null) {
                Map<String, String> config = authenticatorConfig.getConfig();

                if (config != null && config.containsKey(IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION)) {
                    config.put(IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, Boolean.TRUE.toString());
                }

                flows.updateAuthenticatorConfig(authenticatorConfig.getId(), authenticatorConfig);
            }
        }
    }

    static void disableUpdateProfileOnFirstLogin(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {
        if (execution.getProviderId() != null && execution.getProviderId().equals(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID)) {
            execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE.name());
            flows.updateExecutions(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW, execution);
        } else if (execution.getAlias() != null && execution.getAlias().equals(IDP_REVIEW_PROFILE_CONFIG_ALIAS)) {
            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            config.getConfig().put("update.profile.on.first.login", IdentityProviderRepresentation.UPFLM_OFF);
            flows.updateAuthenticatorConfig(config.getId(), config);
        }
    }
}
