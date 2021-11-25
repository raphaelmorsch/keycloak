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

import javax.ws.rs.core.Response;

import org.junit.Test;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.clienttype.ClientTypeManager;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;

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
        ClientRepresentation clientRep = ClientBuilder.create()
                .clientId("foo")
                .type(ClientTypeManager.SERVICE_ACCOUNT)
                .build();

        Response response = testRealm().clients().create(clientRep);
        String clientUUID = ApiUtil.getCreatedId(response);
        getCleanup().addClientUuid(clientUUID);

        clientRep = testRealm().clients().get(clientUUID).toRepresentation();
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
}
