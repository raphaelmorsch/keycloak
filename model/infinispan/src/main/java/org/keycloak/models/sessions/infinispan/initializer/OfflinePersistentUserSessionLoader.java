/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models.sessions.infinispan.initializer;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.infinispan.context.Flag;
import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.common.util.Retry;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.session.UserSessionPersisterProvider;

import java.io.Serializable;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OfflinePersistentUserSessionLoader implements SessionLoader<OfflinePersistentInitialLoaderContext,
        OfflinePersistentLoaderContext, OfflinePersistentWorkerResult>, Serializable {

    private static final Logger log = Logger.getLogger(OfflinePersistentUserSessionLoader.class);

    // Cross-DC aware flag
    public static final String PERSISTENT_SESSIONS_LOADED = "PERSISTENT_SESSIONS_LOADED";

    // Just local-DC aware flag
    public static final String PERSISTENT_SESSIONS_LOADED_IN_CURRENT_DC = "PERSISTENT_SESSIONS_LOADED_IN_CURRENT_DC";


    private final int sessionsPerSegment;

    public OfflinePersistentUserSessionLoader(int sessionsPerSegment) {
        this.sessionsPerSegment = sessionsPerSegment;
    }


    @Override
    public void init(KeycloakSession session) {
        UserSessionPersisterProvider persister = session.getProvider(UserSessionPersisterProvider.class);

        log.debug("Clearing detached sessions from persistent storage");

        persister.clearDetachedUserSessions();
    }


    @Override
    public OfflinePersistentInitialLoaderContext computeInitialLoaderContext(KeycloakSession session) {
        UserSessionPersisterProvider persister = session.getProvider(UserSessionPersisterProvider.class);
        int sessionsCount = persister.getUserSessionsCount(true);

        return new OfflinePersistentInitialLoaderContext(sessionsCount, sessionsPerSegment);
    }


    @Override
    public OfflinePersistentLoaderContext computeLoaderContext(OfflinePersistentInitialLoaderContext initialCtx, int segment, int workerId, List<OfflinePersistentWorkerResult> previousResults) {
        int lastSessionRefresh;
        String lastSessionId;
        if (previousResults.size() == 0) {
            lastSessionRefresh = 0;
            lastSessionId = "abc";
        } else {
            OfflinePersistentWorkerResult lastResult = previousResults.get(previousResults.size());
            lastSessionRefresh = lastResult.getLastLastSessionRefresh();
            lastSessionId = lastResult.getLastSessionId();
        }

        // We know the last loaded session. New workers iteration will start from this place
        return new OfflinePersistentLoaderContext(segment, workerId, lastSessionRefresh, lastSessionId);
    }


    @Override
    public OfflinePersistentWorkerResult createFailedWorkerResult(OfflinePersistentInitialLoaderContext initialLoaderContext, OfflinePersistentLoaderContext loaderContext) {
        return new OfflinePersistentWorkerResult(false, loaderContext.getSegment(), loaderContext.getWorkerId(), -1, "abc");
    }


    @Override
    public OfflinePersistentWorkerResult loadSessions(KeycloakSession session, OfflinePersistentInitialLoaderContext initialCtx, OfflinePersistentLoaderContext ctx) {
        int first = ctx.getWorkerId() * sessionsPerSegment;

        log.tracef("Loading sessions for segment: %d", ctx.getSegment());

        UserSessionPersisterProvider persister = session.getProvider(UserSessionPersisterProvider.class);
        List<UserSessionModel> sessions = persister.loadUserSessions(first, sessionsPerSegment, true, ctx.getLastLastSessionRefresh(), ctx.getLastSessionId());

        log.tracef("Sessions loaded from DB - segment: %d", ctx.getSegment());

        UserSessionModel lastSession = null;
        for (UserSessionModel persistentSession : sessions) {

            // Save to memory/infinispan
            UserSessionModel offlineUserSession = session.sessions().importUserSession(persistentSession, true, true);
            lastSession = offlineUserSession;
        }

        int lastLastSessionRefresh = lastSession==null ? Time.currentTime() + 100000 : lastSession.getLastSessionRefresh();
        String lastSessionId = lastSession==null ? "abc" : lastSession.getId();

        log.tracef("Sessions imported - segment: %d, lastLastSessionRefresh: %s, lastSessionId: %s", ctx.getSegment(), ctx.getLastLastSessionRefresh(), ctx.getLastSessionId());

        return new OfflinePersistentWorkerResult(true, ctx.getSegment(), ctx.getWorkerId(), lastLastSessionRefresh, lastSessionId);
    }


    @Override
    public boolean isFinished(BaseCacheInitializer initializer) {
        Cache<String, Serializable> workCache = initializer.getWorkCache();
        Boolean sessionsLoaded = (Boolean) workCache.get(PERSISTENT_SESSIONS_LOADED);

        if (sessionsLoaded != null && sessionsLoaded) {
            log.debugf("Persistent sessions loaded already.");
            return true;
        } else {
            log.debugf("Persistent sessions not yet loaded.");
            return false;
        }
    }


    @Override
    public void afterAllSessionsLoaded(BaseCacheInitializer initializer) {
        Cache<String, Serializable> workCache = initializer.getWorkCache();

        // Will retry few times for the case when backup site not available in cross-dc environment.
        // The site might be taken offline automatically if "take-offline" properly configured
        Retry.executeWithBackoff((int iteration) -> {

            try {
                // Cross-DC aware flag
                workCache
                        .getAdvancedCache().withFlags(Flag.SKIP_REMOTE_LOOKUP)
                        .put(PERSISTENT_SESSIONS_LOADED, true);

            } catch (HotRodClientException re) {
                log.warnf(re, "Failed to write flag PERSISTENT_SESSIONS_LOADED in iteration '%d' . Retrying", iteration);

                // Rethrow the exception. Retry will take care of handle the exception and eventually retry the operation.
                throw re;
            }

        }, 10, 10);

        // Just local-DC aware flag
        workCache
                .getAdvancedCache().withFlags(Flag.SKIP_REMOTE_LOOKUP, Flag.SKIP_CACHE_LOAD, Flag.SKIP_CACHE_STORE)
                .put(PERSISTENT_SESSIONS_LOADED_IN_CURRENT_DC, true);


        log.debugf("Persistent sessions loaded successfully!");
    }


    @Override
    public String toString() {
        return new StringBuilder("OfflinePersistentUserSessionLoader [ ")
                .append("sessionsPerSegment: ").append(sessionsPerSegment)
                .append(" ]")
                .toString();
    }

}
