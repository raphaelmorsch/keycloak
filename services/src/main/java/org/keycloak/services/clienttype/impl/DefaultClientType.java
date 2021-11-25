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

package org.keycloak.services.clienttype.impl;

import java.lang.reflect.Method;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientTypeRepresentation;
import org.keycloak.services.clienttype.ClientType;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientType implements ClientType {

    private static final Logger logger = Logger.getLogger(DefaultClientType.class);

    private final ClientTypeRepresentation clientType;
    private final Map<String, Method> clientRepresentationSetters;

    public DefaultClientType(ClientTypeRepresentation clientType, Map<String, Method> clientRepresentationSetters) {
        this.clientType = clientType;
        this.clientRepresentationSetters = clientRepresentationSetters;
    }

    @Override
    public boolean isApplicable(String optionName) {
        ClientTypeRepresentation.PropertyConfig cfg = clientType.getConfig().get(optionName);

        // Each property is applicable by default if not configured for the particular client type
        return (cfg != null && cfg.getApplicable() != null) ? cfg.getApplicable() : true;
    }

    @Override
    public boolean isReadOnly(String optionName) {
        ClientTypeRepresentation.PropertyConfig cfg = clientType.getConfig().get(optionName);

        // Each property is writable by default if not configured for the particular type
        return (cfg != null && cfg.getReadOnly() != null) ? cfg.getReadOnly() : false;
    }

    @Override
    public <T> T getConfigValue(String optionName, Class<T> optionType) {
        ClientTypeRepresentation.PropertyConfig cfg = clientType.getConfig().get(optionName);

        return (cfg != null && cfg.getDefaultValue() != null) ? optionType.cast(cfg.getDefaultValue()) : null;
    }

    @Override
    public void onCreate(ClientRepresentation createdClient) {
        for (Map.Entry<String, ClientTypeRepresentation.PropertyConfig> property : clientType.getConfig().entrySet()) {
            ClientTypeRepresentation.PropertyConfig propertyConfig = property.getValue();
            if (!propertyConfig.getApplicable()) continue;
            if (propertyConfig.getDefaultValue() != null) {
                if (clientRepresentationSetters.containsKey(property.getKey())) {
                    // Java property on client representation
                    Method setter = clientRepresentationSetters.get(property.getKey());
                    try {
                        setter.invoke(createdClient, propertyConfig.getDefaultValue());
                    } catch (Exception e) {
                        logger.errorf("Cannot set property '%s' on client with value '%s'. Check configuration of the client type '%s'", property.getKey(), propertyConfig.getDefaultValue(), clientType.getName());
                        throw new IllegalStateException("Cannot set property on client", e);
                    }
                } else {
                    // Client attribute
                    createdClient.getAttributes().put(property.getKey(), propertyConfig.getDefaultValue().toString());
                }
            }
        }
    }

    @Override
    public void onUpdate(ClientModel currentClient, ClientRepresentation clientToUpdate) {
        // Nothing for now
    }
}
