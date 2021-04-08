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
 */

package org.keycloak.protocol.oidc.endpoints.request;

import java.util.Map;
import java.util.Set;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PushedAuthzRequestStoreProvider;
import org.keycloak.models.RealmModel;

import static org.keycloak.protocol.oidc.par.endpoints.ParEndpoint.PAR_CREATED_TIME;

/**
 * Parse the parameters from PAR
 *
 */
class AuthzEndpointParParser extends AuthzEndpointRequestParser {

    private Map<String, String> requestParams;

    private String invalidRequestMessage = null;

    public AuthzEndpointParParser(KeycloakSession session, String requestUri) {
        PushedAuthzRequestStoreProvider parStore = session.getProvider(PushedAuthzRequestStoreProvider.class, "par");
        Map<String, String> retrievedRequest = parStore.remove(requestUri);
        if (retrievedRequest == null) {
            throw new RuntimeException("PAR not found. not issued or used multiple times.");
        }

        RealmModel realm = session.getContext().getRealm();
        int expiresIn = realm.getRequestUriLifespan();
        long created = Long.parseLong(retrievedRequest.get(PAR_CREATED_TIME));
        if (System.currentTimeMillis() - created < (expiresIn * 1000)) {
            requestParams = retrievedRequest;
        } else {
            throw new RuntimeException("PAR expired.");
        }
    }

    @Override
    protected String getParameter(String paramName) {
        return requestParams.get(paramName);
    }

    @Override
    protected Integer getIntParameter(String paramName) {
        String paramVal = requestParams.get(paramName);
        return paramVal == null ? null : Integer.parseInt(paramVal);
    }

    public String getInvalidRequestMessage() {
        return invalidRequestMessage;
    }

    @Override
    protected Set<String> keySet() {
        return requestParams.keySet();
    }

}
