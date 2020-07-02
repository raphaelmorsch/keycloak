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

package org.keycloak.cluster.infinispan;

import java.io.Serializable;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.persistence.remote.configuration.RemoteStoreConfigurationBuilder;
import org.keycloak.cluster.infinispan.test.Book;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JDGProtoStreamTest {

    public static void main(String[] args) throws Exception {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache1 = createManager(1).getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache2 = createManager(2).getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);

        try {
            RemoteCache remoteCache1 = InfinispanUtil.getRemoteCache(cache1);
            RemoteCache remoteCache2 = InfinispanUtil.getRemoteCache(cache2);

            remoteCache1.put("key1", new Book("book1", "desc", 1));
            //remoteCache2.put("key2", );

            Book val1 = (Book) remoteCache2.get("key1");
            System.out.println("Val: " + val1);
        }  finally {
            Thread.sleep(2000);

            // Finish JVM
            cache1.getCacheManager().stop();
            cache2.getCacheManager().stop();
        }
    }

    private static EmbeddedCacheManager createManager(int threadId) {
        return new TestCacheManagerFactory().createManager(threadId, InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, RemoteStoreConfigurationBuilder.class);
    }
}
