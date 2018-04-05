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

package org.keycloak.testsuite.federation.infinispan;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.keycloak.storage.UserStorageProviderFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JDGUserStorageProviderFactory implements UserStorageProviderFactory<JDGUserStorageProvider> {

    public static final String PROVIDER_ID = "jdg";
    public static final String CACHE_NAME = "userStorage";

    private volatile RemoteCache remoteCache;

    @Override
    public JDGUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        if (remoteCache == null) {
            synchronized (this) {
                if (remoteCache == null) {
                    remoteCache = getRemoteCache(session);
                }
            }
        }
        return new JDGUserStorageProvider(session, model, remoteCache);
    }

    static RemoteCache getRemoteCache(KeycloakSession session) {
        InfinispanConnectionProvider ispn = session.getProvider(InfinispanConnectionProvider.class);
        Cache cache = ispn.getCache(CACHE_NAME);
        if (cache == null) {
            throw new IllegalStateException("Cache '" + CACHE_NAME + "' not available");
        }
        RemoteCache remoteCache = InfinispanUtil.getRemoteCache(cache);
        if (remoteCache == null) {
            throw new IllegalStateException("Cache '" + CACHE_NAME + "' must be configured with remoteStore");
        }

        return remoteCache;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
