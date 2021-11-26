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

package org.keycloak.services.clienttype;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientTypeRepresentation;
import org.keycloak.representations.idm.ClientTypesRepresentation;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientTypeManager implements ClientTypeManager {

    private static final Logger logger = Logger.getLogger(DefaultClientTypeManager.class);

    private final KeycloakSession session;
    private final List<ClientTypeRepresentation> globalClientTypes;

    public DefaultClientTypeManager(KeycloakSession session, List<ClientTypeRepresentation> globalClientTypes) {
        this.session = session;
        this.globalClientTypes = globalClientTypes;
    }

    @Override
    public ClientTypesRepresentation getClientTypes(RealmModel realm, boolean includeGlobal) throws ClientTypeException {
        // TODO:mposolda merge global with the realm. Take "includeGlobal" into consideration.
        // TODO:mposolda Don't need to validate global, but needs to validate realm-ones as they were possibly changed
        return new ClientTypesRepresentation(null, globalClientTypes);
    }

    @Override
    public void updateClientTypes(RealmModel realm, ClientTypesRepresentation clientTypes) throws ClientTypeException {
        // TODO:mposolda implement
    }

    @Override
    public ClientType getClientType(KeycloakSession session, RealmModel realm, String typeName) throws ClientTypeException {
        ClientTypesRepresentation clientTypes = getClientTypes(realm, true);
        ClientTypeRepresentation clientType = getClientTypeByName(clientTypes, typeName);
        if (clientType == null) {
            logger.errorf("Referenced client type '%s' not found");
            throw new ClientTypeException("Client type not found");
        }

        ClientTypeProvider provider = session.getProvider(ClientTypeProvider.class, clientType.getProvider());
        return provider.getClientType(clientType);
    }

    private ClientTypeRepresentation getClientTypeByName(ClientTypesRepresentation clientTypes, String clientTypeName) {
        // Search realm clientTypes
        if (clientTypes.getRealmClientTypes() != null) {
            for (ClientTypeRepresentation clientType : clientTypes.getRealmClientTypes()) {
                if (clientTypeName.equals(clientType.getName())) {
                    return clientType;
                }
            }
        }
        // Search global clientTypes
        if (clientTypes.getGlobalClientTypes() != null) {
            for (ClientTypeRepresentation clientType : clientTypes.getGlobalClientTypes()) {
                if (clientTypeName.equals(clientType.getName())) {
                    return clientType;
                }
            }
        }
        return null;
    }
}
