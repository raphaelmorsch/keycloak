/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.client;

import java.util.List;
import java.util.stream.Collectors;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;

import org.junit.Test;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientTypeRepresentation;
import org.keycloak.representations.idm.ClientTypesRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.clienttype.ClientType;
import org.keycloak.services.clienttype.ClientTypeManager;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientTypesTest extends AbstractTestRealmKeycloakTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }


    // Test create client with clientType filled. Check default properties are filled
    @Test
    public void testCreateClientWithClientType() {
        ClientRepresentation clientRep = createClientWithType("foo", ClientTypeManager.SERVICE_ACCOUNT);
        Assert.assertEquals("foo", clientRep.getClientId());
        Assert.assertEquals(ClientTypeManager.SERVICE_ACCOUNT, clientRep.getType());
        Assert.assertEquals(OIDCLoginProtocol.LOGIN_PROTOCOL, clientRep.getProtocol());
        Assert.assertFalse(clientRep.isStandardFlowEnabled());
        Assert.assertFalse(clientRep.isImplicitFlowEnabled());
        Assert.assertFalse(clientRep.isDirectAccessGrantsEnabled());
        Assert.assertTrue(clientRep.isServiceAccountsEnabled());
        Assert.assertFalse(clientRep.isPublicClient());
        Assert.assertFalse(clientRep.isBearerOnly());
    }

    @Test
    public void testUpdateClientWithClientType() {
        ClientRepresentation clientRep = createClientWithType("foo", ClientTypeManager.SERVICE_ACCOUNT);

        // Changing type should fail
        clientRep.setType(ClientTypeManager.SLA);
        try {
            testRealm().clients().get(clientRep.getId()).update(clientRep);
            Assert.fail("Not expected to update client");
        } catch (BadRequestException bre) {
            // Expected
        }

        // Updating read-only attribute should fail
        clientRep.setType(ClientTypeManager.SERVICE_ACCOUNT);
        clientRep.setServiceAccountsEnabled(false);
        try {
            testRealm().clients().get(clientRep.getId()).update(clientRep);
            Assert.fail("Not expected to update client");
        } catch (BadRequestException bre) {
            // Expected
        }

        // Adding non-applicable attribute should fail
        clientRep.setServiceAccountsEnabled(true);
        clientRep.getAttributes().put(ClientModel.LOGO_URI, "https://foo");
        try {
            testRealm().clients().get(clientRep.getId()).update(clientRep);
            Assert.fail("Not expected to update client");
        } catch (BadRequestException bre) {
            // Expected
        }

        // Update of supported attribute should be successful
        clientRep.getAttributes().remove(ClientModel.LOGO_URI);
        clientRep.setRootUrl("https://foo");
        testRealm().clients().get(clientRep.getId()).update(clientRep);
    }

    @Test
    public void testClientTypesAdminRestAPI() {
        ClientTypesRepresentation clientTypes = testRealm().clientTypes().getClientTypes(true);

        // TODO:mposolda likely should not be null
        Assert.assertNull(clientTypes.getRealmClientTypes());

        List<String> globalClientTypeNames = clientTypes.getGlobalClientTypes().stream()
                .map(ClientTypeRepresentation::getName)
                .collect(Collectors.toList());
        Assert.assertNames(globalClientTypeNames, "sla", "service-account");

        ClientTypeRepresentation serviceAccountType = clientTypes.getGlobalClientTypes().stream()
                .filter(clientType -> "service-account".equals(clientType.getName()))
                .findFirst()
                .get();
        Assert.assertEquals("default", serviceAccountType.getProvider());

        ClientTypeRepresentation.PropertyConfig cfg = serviceAccountType.getConfig().get("standardFlowEnabled");
        assertPropertyConfig("standardFlowEnabled", cfg, true, true, false);

        cfg = serviceAccountType.getConfig().get("serviceAccountsEnabled");
        assertPropertyConfig("serviceAccountsEnabled", cfg, true, true, true);

        cfg = serviceAccountType.getConfig().get("tosUri");
        assertPropertyConfig("tosUri", cfg, false, null, null);

        // TODO:mposolda test for updates and "includeGlobal=false"
    }

    private void assertPropertyConfig(String propertyName, ClientTypeRepresentation.PropertyConfig cfg, Boolean expectedApplicable, Boolean expectedReadOnly, Object expectedDefaultValue) {
        assertThat("'applicable' for property " + propertyName + " not equal", ObjectUtil.isEqualOrBothNull(expectedApplicable, cfg.getApplicable()));
        assertThat("'read-only' for property " + propertyName + " not equal", ObjectUtil.isEqualOrBothNull(expectedReadOnly, cfg.getReadOnly()));
        assertThat("'default-value' for property " + propertyName + " not equal", ObjectUtil.isEqualOrBothNull(expectedDefaultValue, cfg.getDefaultValue()));
    }

    private ClientRepresentation createClientWithType(String clientId, String clientType) {
        ClientRepresentation clientRep = ClientBuilder.create()
                .clientId(clientId)
                .type(clientType)
                .build();

        Response response = testRealm().clients().create(clientRep);
        String clientUUID = ApiUtil.getCreatedId(response);
        getCleanup().addClientUuid(clientUUID);

        return testRealm().clients().get(clientUUID).toRepresentation();
    }
}
