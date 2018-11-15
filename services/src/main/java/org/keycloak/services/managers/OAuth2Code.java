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

package org.keycloak.services.managers;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Single-use oauth2 code
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OAuth2Code {

    private static final String ID_NOTE = "id";
    private static final String EXPIRATION_NOTE = "exp";
    private static final String USER_SESSION_ID_NOTE = "uss";
    private static final String CLIENT_UUID_NOTE = "clientUUID";
    private static final String NONCE_NOTE = "nonce";
    private static final String SCOPE_NOTE = "scope";
    private static final String REDIRECT_URI_PARAM_NOTE = "redirectUri";
    private static final String CODE_CHALLENGE_NOTE = "code_challenge";
    private static final String CODE_CHALLENGE_METHOD_NOTE = "code_challenge_method";

    private final UUID id;

    private final int expiration;

    private final String userSessionId;

    private final String clientUUID;

    private final String nonce;

    private final String scope;

    private final String redirectUriParam;

    private final String codeChallenge;

    private final String codeChallengeMethod;


    private OAuth2Code(Map<String, String> data) {
        id = UUID.fromString(data.get(ID_NOTE));
        expiration = Integer.parseInt(data.get(EXPIRATION_NOTE));
        // TODO:mposolda
    }


    public static final OAuth2Code deserializeCode(Map<String, String> data) {
        return new OAuth2Code(data);
    }


    public Map<String, String> serializeCode() {
        Map<String, String> result = new HashMap<>();
        result.put(ID_NOTE, id.toString());
        result.put(EXPIRATION_NOTE, String.valueOf(expiration));
        // TODO:mposolda

        return result;
    }


    public UUID getId() {
        return id;
    }

    public int getExpiration() {
        return expiration;
    }

    public String getUserSessionId() {
        return userSessionId;
    }

    public String getClientUUID() {
        return clientUUID;
    }

    public String getNonce() {
        return nonce;
    }

    public String getScope() {
        return scope;
    }

    public String getRedirectUriParam() {
        return redirectUriParam;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
}
