package org.keycloak.testsuite.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.atomic.AtomicReference;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.arquillian.annotation.ModelTest;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.RealmBuilder;

import static org.keycloak.testsuite.arquillian.DeploymentTargetModifier.AUTH_SERVER_CURRENT;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CredentialModelTest extends AbstractTestRealmKeycloakTest {

    @Deployment
    @TargetsContainer(AUTH_SERVER_CURRENT)
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class, UserModelTest.class)
                .addPackages(true,
                        "org.keycloak.testsuite",
                        "org.keycloak.testsuite.model",
                        "com.google.common");
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {

    }


    @Test
    @ModelTest
    public void testCredentialCRUD(KeycloakSession session) throws Exception {
        AtomicReference<String> passwordId = new AtomicReference<>();
        AtomicReference<String> otp1Id = new AtomicReference<>();
        AtomicReference<String> otp2Id = new AtomicReference<>();

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");

            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            Assert.assertEquals(1, list.size());
            passwordId.set(list.get(0).getId());

            // Create 2 OTP credentials (password was already created)
            CredentialModel otp1 = OTPCredentialModel.createFromPolicy(realm, "secret1");
            CredentialModel otp2 = OTPCredentialModel.createFromPolicy(realm, "secret2");
            otp1 = currentSession.userCredentialManager().createCredential(realm, user, otp1);
            otp2 = currentSession.userCredentialManager().createCredential(realm, user, otp2);
            otp1Id.set(otp1.getId());
            otp2Id.set(otp2.getId());
        });


        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);

            // Assert priorities: password, otp1, otp2
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            assertOrder(list, passwordId.get(), otp1Id.get(), otp2Id.get());

            // Assert can't move password up
            Assert.assertFalse(currentSession.userCredentialManager().moveCredential(realm, user, passwordId.get(), true));

            // Assert can't move otp2 down
            Assert.assertFalse(currentSession.userCredentialManager().moveCredential(realm, user, otp2Id.get(), false));

            // Move otp2 up
            Assert.assertTrue(currentSession.userCredentialManager().moveCredential(realm, user, otp2Id.get(), true));
        });

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);

            // Assert priorities: password, otp2, otp1
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            assertOrder(list, passwordId.get(), otp2Id.get(), otp1Id.get());

            // Move otp2 up
            Assert.assertTrue(currentSession.userCredentialManager().moveCredential(realm, user, otp2Id.get(), true));
        });

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);

            // Assert priorities: otp2, password, otp1
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            assertOrder(list, otp2Id.get(), passwordId.get(), otp1Id.get());

            // Move password down
            Assert.assertTrue(currentSession.userCredentialManager().moveCredential(realm, user, passwordId.get(), false));
        });

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);

            // Assert priorities: otp2, otp1, password
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            assertOrder(list, otp2Id.get(), otp1Id.get(), passwordId.get());

            // Remove otp1
            Assert.assertTrue(currentSession.userCredentialManager().removeStoredCredential(realm, user, otp1Id.get()));
        });

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), (KeycloakSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            UserModel user = currentSession.users().getUserByUsername("test-user@localhost", realm);

            // Assert priorities: otp2, password
            List<CredentialModel> list = currentSession.userCredentialManager().getStoredCredentials(realm, user);
            assertOrder(list, otp2Id.get(), passwordId.get());
        });
    }


    private void assertOrder(List<CredentialModel> creds, String... expectedIds) {
        Assert.assertEquals(expectedIds.length, creds.size());

        if (creds.size() == 0) return;

        for (int i=0 ; i<expectedIds.length ; i++) {
            Assert.assertEquals(creds.get(i).getId(), expectedIds[i]);
        }
    }

}
