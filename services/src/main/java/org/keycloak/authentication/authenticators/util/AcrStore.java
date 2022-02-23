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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * TODO:mposolda
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AcrStore {

    private static final Logger LOGGER = Logger.getLogger(AcrStore.class);

    private final Function<String, String> getNote;
    private final BiConsumer<String, String> setNote;

    public AcrStore(AuthenticationSessionModel authSession) {
        this.getNote = authSession::getAuthNote;
        this.setNote = authSession::setAuthNote;
    }

    public AcrStore(UserSessionModel userSession) {
        this.getNote = userSession::getNote;
        this.setNote = userSession::setNote;
    }


    /**
     * True if the particular level was achieved and still valid
     *
     * @param level
     * @param maxAge maxAge for which this level is considered valid
     * @return
     */
    public boolean isLevelAuthenticated(int level, int maxAge) {
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevels();
        if (levels == null) return false;

        AcrLevelInfo levelInfo = levels.get(level);
        if (levelInfo == null) return false;

        int currentTime = Time.currentTime();
        return levelInfo.authTime + maxAge >= currentTime;
    }

    /**
     * Save authenticated level to userSession
     *
     * @param level level to save
     * @param maxAge maxAge for the particular level in seconds. After this time, the level is not considered valid anymore and user
     *               should be prompted for re-authentication with this level (if this level is asked during authentication)
     */
    public void setLevelAuthenticated(int level, int maxAge) {
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevels();
        if (levels == null) levels = new HashMap<>();

        AcrLevelInfo levelInfo = new AcrLevelInfo();
        levelInfo.authTime = Time.currentTime();
        levelInfo.expiration = levelInfo.authTime + maxAge;
        levels.put(level, levelInfo);

        saveCurrentAuthenticatedLevels(levels);
    }


    /**
     * @return highest achieved authenticated level, which is not expired. There must not be any other expired level lower than returned level.
     * So if level X is expired, the highest returned level from this method can be at max (X-1).
     */
    public int getAuthenticatedLevel() {
        // No map found. User was not yet authenticated in this session
        Map<Integer, AcrLevelInfo> levels = getCurrentAuthenticatedLevels();
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

    private Map<Integer, AcrLevelInfo> getCurrentAuthenticatedLevels() {
        String loaMap = getNote(Constants.LOA_MAP);
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

    private void saveCurrentAuthenticatedLevels(Map<Integer, AcrLevelInfo> levelInfoMap) {
        try {
            String note = JsonSerialization.writeValueAsString(levelInfoMap);
            setNote(Constants.LOA_MAP, note);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }


    private String getNote(String key) {
        return getNote.apply(key);
    }

    private void setNote(String key, String value) {
        setNote.accept(key, value);
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
