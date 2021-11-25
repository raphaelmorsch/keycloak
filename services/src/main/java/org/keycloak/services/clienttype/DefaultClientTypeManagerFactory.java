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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.representations.idm.ClientTypeRepresentation;
import org.keycloak.representations.idm.ClientTypesRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientTypeManagerFactory implements ClientTypeManagerFactory {

    private static final Logger logger = Logger.getLogger(DefaultClientTypeManagerFactory.class);

    private volatile List<ClientTypeRepresentation> globalClientTypes;

    @Override
    public ClientTypeManager create(KeycloakSession session) {
        return new DefaultClientTypeManager(session, getGlobalClientTypes(session));
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "default";
    }


    protected List<ClientTypeRepresentation> getGlobalClientTypes(KeycloakSession session) {
        if (globalClientTypes == null) {
            synchronized (this) {
                if (globalClientTypes == null) {
                    // TODO:mposolda debug
                    logger.info("Loading global client types");

                    try {
                        ClientTypesRepresentation globalTypesRep  = JsonSerialization.readValue(getClass().getResourceAsStream("/keycloak-default-client-types.json"), ClientTypesRepresentation.class);

                        List<ClientTypeRepresentation> globalTypes = new ArrayList<>();

                        // Validate globalTypes in correct format
                        for (ClientTypeRepresentation clientType : globalTypesRep.getClientTypes()) {
                            globalTypes.add(validateAndCastConfiguration(session, clientType));
                        }

                        this.globalClientTypes = globalTypes;
                    } catch (IOException e) {
                        throw new IllegalStateException("Failed to deserialize global proposed client types from JSON.", e);
                    }
                }
            }
        }
        return globalClientTypes;
    }


    private ClientTypeRepresentation validateAndCastConfiguration(KeycloakSession session, ClientTypeRepresentation clientType) {
        ClientTypeProvider clientTypeProvider = session.getProvider(ClientTypeProvider.class, clientType.getProvider());
        if (clientTypeProvider == null) {
            logger.errorf("Did not found client type provider '%s' for the client type '%s'", clientType.getProvider(), clientType.getName());
            throw new IllegalStateException("Did not found client type provider");
        }
        return clientTypeProvider.validateAndCastClientTypeConfig(clientType);
    }
}
