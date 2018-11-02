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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.infinispan.Cache;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.Configuration;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.jgroups.JChannel;
import org.junit.Ignore;
import org.keycloak.common.util.Time;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.SessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import java.util.UUID;

/**
 * Test concurrent writes to distributed cache with usage of atomic replace
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Ignore
public class DistributedCacheConcurrentWritesTest {

    private static final int BATCHES_PER_WORKER = 1000;
    private static final int ITEMS_IN_BATCH = 100;

    public static void main(String[] args) throws Exception {
        CacheWrapper<String, UserSessionEntity> cache1 = createCache("node1");
        CacheWrapper<String, UserSessionEntity> cache2 = createCache("node2");

        try {
            testConcurrentPut(cache1, cache2);
        } finally {

            // Kill JVM
            cache1.getCache().stop();
            cache2.getCache().stop();
            cache1.getCache().getCacheManager().stop();
            cache2.getCache().getCacheManager().stop();

            System.out.println("Managers killed");
        }
    }


    private static UserSessionEntity createEntityInstance(String id) {
        // Create initial item
        UserSessionEntity session = new UserSessionEntity();
        session.setId(id);
        session.setRealmId("foo");
        session.setBrokerSessionId("!23123123");
        session.setBrokerUserId(null);
        session.setUser("foo");
        session.setLoginUsername("foo");
        session.setIpAddress("123.44.143.178");
        session.setStarted(Time.currentTime());
        session.setLastSessionRefresh(Time.currentTime());

        AuthenticatedClientSessionEntity clientSession = new AuthenticatedClientSessionEntity(UUID.randomUUID());
        clientSession.setAuthMethod("saml");
        clientSession.setAction("something");
        clientSession.setTimestamp(1234);
        session.getAuthenticatedClientSessions().put("foo-client", clientSession.getId());

        return session;
    }


    // Reproducer for KEYCLOAK-7443 and KEYCLOAK-7489. The infinite loop can happen if cache.replace(key, old, new) is called and entity was removed on one cluster node in the meantime
    private static void testConcurrentPut(CacheWrapper<String, UserSessionEntity> cache1,
                                          CacheWrapper<String, UserSessionEntity> cache2) throws InterruptedException {

        // Create workers for concurrent write and start them
        Worker worker1 = new Worker(1, cache1);
        Worker worker2 = new Worker(2, cache2);

        long start = System.currentTimeMillis();

        System.out.println("Started clustering test");

        worker1.start();
        //worker1.join();
        worker2.start();

        worker1.join();
        worker2.join();

        long took = System.currentTimeMillis() - start;

        System.out.println("Test finished. Took: " + took + " ms. Cache size: " + cache1.getCache().size());

        // JGroups statistics
        JChannel channel = ((JGroupsTransport)cache1.wrappedCache.getAdvancedCache().getRpcManager().getTransport()).getChannel();
        System.out.println("Sent MB: " + channel.getSentBytes() / 1000000 + ", sent messages: " + channel.getSentMessages() + ", received MB: " + channel.getReceivedBytes() / 1000000 +
                ", received messages: " + channel.getReceivedMessages());
    }


    private static class Worker extends Thread {

        private final CacheWrapper<String, UserSessionEntity> cache;
        private final int startIndex;

        public Worker(int threadId, CacheWrapper<String, UserSessionEntity> cache) {
            this.cache = cache;
            this.startIndex = (threadId - 1) * (ITEMS_IN_BATCH * BATCHES_PER_WORKER);
            setName("th-" + threadId);
        }

        @Override
        public void run() {

            for (int page = 0; page < BATCHES_PER_WORKER ; page++) {
                int startPageIndex = startIndex + page * ITEMS_IN_BATCH;

                //putItemsClassic(startPageIndex);
                putItemsAll(startPageIndex);

                System.out.println("Thread " + getName() + ": Saved items from " + startPageIndex + " to " + (startPageIndex + ITEMS_IN_BATCH - 1));
            }
        }


        // put items 1 by 1
        private void putItemsClassic(int startPageIndex) {
            for (int i = startPageIndex ; i < (startPageIndex + ITEMS_IN_BATCH) ; i++) {
                String key = "key-" + startIndex + i;
                UserSessionEntity session = createEntityInstance(key);
                cache.put(key, session);
            }
        }


        // put all items together
        private void putItemsAll(int startPageIndex) {
            Map<String, SessionEntityWrapper<UserSessionEntity>> mapp = new HashMap<>();

            for (int i = startPageIndex ; i < (startPageIndex + ITEMS_IN_BATCH) ; i++) {
                String key = "key-" + startIndex + i;
                UserSessionEntity session = createEntityInstance(key);
                mapp.put(key, new SessionEntityWrapper<>(session));
            }

            cache.getCache().putAll(mapp);
        }
    }


    // Cache creation utils

    public static class CacheWrapper<K, V extends SessionEntity> {

        private final Cache<K, SessionEntityWrapper<V>> wrappedCache;

        public CacheWrapper(Cache<K, SessionEntityWrapper<V>> wrappedCache) {
            this.wrappedCache = wrappedCache;
        }


        public SessionEntityWrapper<V> get(K key) {
            SessionEntityWrapper<V> val = wrappedCache.get(key);
            return val;
        }

        public void put(K key, V newVal) {
            SessionEntityWrapper<V> newWrapper = new SessionEntityWrapper<>(newVal);
            wrappedCache.put(key, newWrapper);
        }


        public boolean replace(K key, SessionEntityWrapper<V> oldVal, V newVal) {
            SessionEntityWrapper<V> newWrapper = new SessionEntityWrapper<>(newVal);
            return wrappedCache.replace(key, oldVal, newWrapper);
        }

        private Cache<K, SessionEntityWrapper<V>> getCache() {
            return wrappedCache;
        }

    }


    public static CacheWrapper<String, UserSessionEntity> createCache(String nodeName) {
        EmbeddedCacheManager mgr = createManager(nodeName);
        Cache<String, SessionEntityWrapper<UserSessionEntity>> wrapped = mgr.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
        return new CacheWrapper<>(wrapped);
    }


    public static EmbeddedCacheManager createManager(String nodeName) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        System.setProperty("jgroups.tcp.port", "53715");
        GlobalConfigurationBuilder gcb = new GlobalConfigurationBuilder();

        boolean clustered = true;
        boolean async = false;
        boolean allowDuplicateJMXDomains = true;

        if (clustered) {
            gcb = gcb.clusteredDefault();
            gcb.transport().clusterName("test-clustering");
            gcb.transport().nodeName(nodeName);
        }
        gcb.globalJmxStatistics().allowDuplicateDomains(allowDuplicateJMXDomains);

        EmbeddedCacheManager cacheManager = new DefaultCacheManager(gcb.build());


        ConfigurationBuilder distConfigBuilder = new ConfigurationBuilder();
        if (clustered) {
            distConfigBuilder.clustering().cacheMode(async ? CacheMode.DIST_ASYNC : CacheMode.DIST_SYNC);
            distConfigBuilder.clustering().hash().numOwners(1);

            // Disable L1 cache
            distConfigBuilder.clustering().hash().l1().enabled(false);
        }
        Configuration distConfig = distConfigBuilder.build();

        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, distConfig);
        return cacheManager;

    }
}
