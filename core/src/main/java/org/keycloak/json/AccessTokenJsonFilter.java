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

package org.keycloak.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import org.keycloak.representations.AccessToken;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AccessTokenJsonFilter extends SimpleBeanPropertyFilter {

    private static final String RESOURCE_ACCESS = "resource_access";

    @Override
    public void serializeAsField(Object pojo, JsonGenerator jgen,
                                 SerializerProvider provider, PropertyWriter writer) throws Exception {
        if (pojo instanceof AccessToken && RESOURCE_ACCESS.equals(writer.getName())) {
            AccessToken accessToken = (AccessToken) pojo;

            // Don't serialize "resourceAccess" property if it is null and we have "resource_access" in the otherClaims
            if (accessToken.getResourceAccess() != null && accessToken.getResourceAccess().isEmpty() && accessToken.getOtherClaims().containsKey(RESOURCE_ACCESS)) {
                return;
            }
        }

        super.serializeAsField(pojo, jgen, provider, writer);
    }
}
