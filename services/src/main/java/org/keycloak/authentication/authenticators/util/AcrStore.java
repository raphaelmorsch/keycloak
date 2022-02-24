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

package org.keycloak.authentication.authenticators.util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiConsumer;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * TODO:mposolda
 *
 * TODO:mposolda more logging?
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AcrStore {

    private static final Logger LOGGER = Logger.getLogger(AcrStore.class);

    // TODO:mposolda comment or javadoc
    private final AuthenticationSessionModel authSession;

    public AcrStore(AuthenticationSessionModel authSession) {
        this.authSession = authSession;
    }

    public int getRequestedLevelOfAuthentication() {
        String requiredLoa = authSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION);
        return requiredLoa == null ? Constants.NO_LOA : Integer.parseInt(requiredLoa);
    }

    public boolean isLevelOfAuthenticationSatisfiedFromPreviousAuthentication() {
        return getRequestedLevelOfAuthentication()
                <= getAuthenticatedLevelFromPreviousAuthentication();
    }

    public boolean isLevelOfAuthenticationSatisfiedFromCurrentAuthentication() {
        return getRequestedLevelOfAuthentication()
                <= getAuthenticatedLevelCurrentAuthentication();
    }


    /**
     * True if the particular level was achieved and still valid
     *
     * @param level
     * @param maxAge maxAge for which this level is considered valid
     * @return
     */
    public boolean isLevelAuthenticatedInPreviousAuth(int level, int maxAge) {
        // TODO:mposolda This considers just the map. Which is probably OK
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevelsMap();
        if (levels == null) return false;

        AcrLevelInfo levelInfo = levels.get(level);
        if (levelInfo == null) return false;

        int currentTime = Time.currentTime();
        return levelInfo.authTime + maxAge >= currentTime;
    }

    // TODO:mposolda javadoc
    public int getLevelOfAuthenticationFromCurrentAuthentication() {
        String authSessionLoaNote = authSession.getAuthNote(Constants.LEVEL_OF_AUTHENTICATION);
        return authSessionLoaNote == null ? Constants.NO_LOA : Integer.parseInt(authSessionLoaNote);
    }

    /**
     * Save authenticated level to userSession
     *
     * @param level level to save
     * @param maxAge maxAge for the particular level in seconds. After this time, the level is not considered valid anymore and user
     *               should be prompted for re-authentication with this level (if this level is asked during authentication)
     */
    public void setLevelAuthenticated(int level, int maxAge) {
        setLevelAuthenticatedToCurrentRequest(level);
        setLevelAuthenticatedToMap(level, maxAge);
    }

    public void setLevelAuthenticatedToCurrentRequest(int level) {
        authSession.setAuthNote(Constants.LEVEL_OF_AUTHENTICATION, String.valueOf(level));
    }

    private void setLevelAuthenticatedToMap(int level, int maxAge) {
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevelsMap();
        if (levels == null) levels = new HashMap<>();

        AcrLevelInfo levelInfo = new AcrLevelInfo();
        levelInfo.authTime = Time.currentTime();
        levelInfo.expiration = levelInfo.authTime + maxAge;
        levels.put(level, levelInfo);

        saveCurrentAuthenticatedLevelsMap(levels);
    }


    /**
     * @return highest achieved authenticated level, which is not expired. There must not be any other expired level lower than returned level.
     * So if level X is expired, the highest returned level from this method can be at max (X-1).
     */
    public int getAuthenticatedLevel() {
        int levelFromCurrentRequest = getAuthenticatedLevelCurrentAuthentication();
        int levelFromSession = getAuthenticatedLevelFromPreviousAuthentication();

        return Math.max(levelFromCurrentRequest, levelFromSession);
    }

    private int getAuthenticatedLevelCurrentAuthentication() {
        String authSessionLoaNote = authSession.getAuthNote(Constants.LEVEL_OF_AUTHENTICATION);
        return authSessionLoaNote == null ? Constants.NO_LOA : Integer.parseInt(authSessionLoaNote);
    }

    public int getAuthenticatedLevelFromPreviousAuthentication() {
        // No map found. User was not yet authenticated in this session
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevelsMap();
        if (levels == null || levels.isEmpty()) return Constants.NO_LOA;

        // Map was already saved, so it is SSO authentication at minimum. Using "0" level as the minimum level in this case
        int maxLevel = Constants.MINIMUM_LOA;
        int currentTime = Time.currentTime();

        levels = new TreeMap<>(levels);

        for (Map.Entry<Integer, AcrLevelInfo> entry : levels.entrySet()) {
            int levelExpiration = entry.getValue().expiration;
            if (currentTime <= levelExpiration) {
                maxLevel = entry.getKey();
            } else {
                return maxLevel;
            }
        }

        return maxLevel;
    }

    private Map<Integer, AcrLevelInfo> getCurrentAuthenticatedLevelsMap() {
        String loaMap = authSession.getAuthNote(Constants.LOA_MAP);
        if (loaMap == null) {
            return null;
        }
        try {
            return JsonSerialization.readValue(loaMap, new TypeReference<Map<Integer, AcrLevelInfo>>() {});
        } catch (IOException e) {
            LOGGER.warnf("Invalid format of the LoA map. Saved value was: %s", loaMap);
            throw new IllegalStateException(e);
        }
    }

    private void saveCurrentAuthenticatedLevelsMap(Map<Integer, AcrLevelInfo> levelInfoMap) {
        try {
            String note = JsonSerialization.writeValueAsString(levelInfoMap);
            authSession.setAuthNote(Constants.LOA_MAP, note);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // Track both expiration and authTime of current level in the userSession.
    // We use expiration to check latest achieved level. We use authTime during authentication
    // (expiration may not be sufficient in case that condition configuration changed in the authentication flow and condition expiration in the configuration was set to lower value)
    private static class AcrLevelInfo {

        @JsonProperty("authTime")
        private Integer authTime;

        @JsonProperty("expiration")
        private Integer expiration;
    }

}
