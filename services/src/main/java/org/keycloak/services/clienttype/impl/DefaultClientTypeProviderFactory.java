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

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clienttype.ClientTypeProvider;
import org.keycloak.services.clienttype.ClientTypeProviderFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientTypeProviderFactory implements ClientTypeProviderFactory {

    private Map<String, PropertyDescriptor> clientRepresentationSetters;

    @Override
    public ClientTypeProvider create(KeycloakSession session) {
        return new DefaultClientTypeProvider(session, clientRepresentationSetters);
    }

    @Override
    public void init(Config.Scope config) {
        try {
            BeanInfo bi = Introspector.getBeanInfo(ClientRepresentation.class);
            PropertyDescriptor[] pd = bi.getPropertyDescriptors();
            clientRepresentationSetters = Arrays.stream(pd)
                    .filter(desc -> !desc.getName().equals("attributes"))
                    .filter(desc -> desc.getWriteMethod() != null)
                    .collect(Collectors.toMap(PropertyDescriptor::getName, Function.identity()));
        } catch (IntrospectionException ie) {
            throw new IllegalStateException("Introspection of Client representation failed", ie);
        }
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
}
