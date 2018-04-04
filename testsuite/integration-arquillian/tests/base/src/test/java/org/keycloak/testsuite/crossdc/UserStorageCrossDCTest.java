/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.crossdc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.client.KeycloakTestingClient;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;


/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class UserStorageCrossDCTest extends AbstractAdminCrossDCTest {

    @Deployment(name = "dc0")
    @TargetsContainer(QUALIFIER_AUTH_SERVER_DC_0_NODE_1)
    public static WebArchive deployDC0() {
        return RunOnServerDeployment.create(
                BruteForceCrossDCTest.class,
                AbstractAdminCrossDCTest.class,
                AbstractCrossDCTest.class,
                AbstractTestRealmKeycloakTest.class,
                UserStorageCrossDCTest.class,
                KeycloakTestingClient.class
        );
    }

    @Deployment(name = "dc1")
    @TargetsContainer(QUALIFIER_AUTH_SERVER_DC_1_NODE_1)
    public static WebArchive deployDC1() {
        return RunOnServerDeployment.create(
                BruteForceCrossDCTest.class,
                AbstractAdminCrossDCTest.class,
                AbstractCrossDCTest.class,
                AbstractTestRealmKeycloakTest.class,
                UserStorageCrossDCTest.class,
                KeycloakTestingClient.class
        );
    }


    @Before
    public void reImportRealms() {
        log.infof("Re-importing realms");

        // Re-import realm in DB1
        KeycloakTestingClient testingClient1 = getTestingClientForStartedNodeInDc(0);
        testingClient1.server().run(session -> {

            reImportRealm(session);

        });

        // Re-import realm in DB2
        KeycloakTestingClient testingClient2 = getTestingClientForStartedNodeInDc(1);
        testingClient2.server().run(session -> {

            reImportRealm(session);

        });
    }

    private static final String SUMMIT_REALM = "summit";

    public static void reImportRealm(KeycloakSession session) {
        // Check if realm exists. Delete if yes
        RealmManager mgr = new RealmManager(session);
        RealmModel realm = mgr.getRealmByName(SUMMIT_REALM);
        if (realm != null) {
            mgr.removeRealm(realm);
        }

        String realmFile = System.getProperty("realm.file");

        // Import realm
        try {
            RealmRepresentation rep = loadJson(new FileInputStream(realmFile), RealmRepresentation.class);
            realm = mgr.importRealm(rep);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }


    @Test
    public void loginTest() throws Exception {
        enableDcOnLoadBalancer(DC.SECOND);

        //log.infof("Sleeping");
        //Thread.sleep(30000000);

        // Add user with email in DC1
        KeycloakTestingClient testingClient1 = getTestingClientForStartedNodeInDc(0);
        testingClient1.server().run(session -> {
            RealmModel realm = session.realms().getRealmByName(SUMMIT_REALM);
            UserModel user = session.users().addUser(realm, "john@email.cz");
            user.setEnabled(true);
            user.setEmail("john@email.cz");
        });

        // Check user is available on DC2
        KeycloakTestingClient testingClient2 = getTestingClientForStartedNodeInDc(1);
        testingClient2.server().run(session -> {
            RealmModel realm = session.realms().getRealmByName(SUMMIT_REALM);
            UserModel user = session.users().getUserByEmail("john@email.cz", realm);
            Assert.assertNotNull(user);
            Assert.assertEquals("john@email.cz", user.getUsername());
            Assert.assertEquals("john@email.cz", user.getEmail());
            Assert.assertTrue(user.isEnabled());
        });

    }
}
