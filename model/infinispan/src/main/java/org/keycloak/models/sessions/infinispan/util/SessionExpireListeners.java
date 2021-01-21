/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models.sessions.infinispan.util;

import java.io.Serializable;
import java.util.UUID;
import java.util.concurrent.Future;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.notifications.Listener;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryExpired;
import org.infinispan.notifications.cachelistener.event.CacheEntryExpiredEvent;
import org.jboss.logging.Logger;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;

/**
 *
 * NOTE: On distributed caches, listeners are triggered just on the owner node
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SessionExpireListeners {

    private static final Logger logger = Logger.getLogger(SessionExpireListeners.class);


    @Listener(observation = Listener.Observation.POST)
    public static class UserSessionCacheListener {

        private final RemoteCache remoteCache;
        private final Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache;

        public UserSessionCacheListener(RemoteCache remoteCache, Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache) {
            this.remoteCache = remoteCache;
            this.clientSessionCache = clientSessionCache;
        }

        @CacheEntryExpired
        public void cacheEntryExpired(CacheEntryExpiredEvent<String, SessionEntityWrapper<UserSessionEntity>> event) {
            // TODO:mposolda trace
            logger.infof("Expired session from the cache '%s' . Session: %s", event.getValue());

            UserSessionEntity userSessionEntity = event.getValue().getEntity();

            // Propagate removal of expired session to remoteCache
            if (remoteCache != null) {
                remoteCache.remove(event.getKey());
            }

            // Remove expired client sessions
            userSessionEntity.getAuthenticatedClientSessions().forEach((clientUUID, clientSessionId) -> {
                clientSessionCache.removeAsync(clientSessionId);
            });
        }

    }

    @Listener(observation = Listener.Observation.POST)
    public static class ClientSessionCacheListener {

        private final RemoteCache remoteCache;

        public ClientSessionCacheListener(RemoteCache remoteCache) {
            this.remoteCache = remoteCache;
        }

        @CacheEntryExpired
        public void cacheEntryExpired(CacheEntryExpiredEvent<String, SessionEntityWrapper<AuthenticatedClientSessionEntity>> event) {
            // TODO:mposolda trace
            logger.infof("Expired session from the cache '%s' . Session: %s", event.getValue());

            // RemoteCache is not null. Otherwise this listener is not added
            remoteCache.remove(event.getKey());
        }

    }

}
