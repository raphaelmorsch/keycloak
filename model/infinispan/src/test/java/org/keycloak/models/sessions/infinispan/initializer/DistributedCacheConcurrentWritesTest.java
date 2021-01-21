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
import java.util.Map;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.ProtocolVersion;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.commons.api.BasicCache;
import org.infinispan.commons.time.TimeService;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.Configuration;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.factories.GlobalComponentRegistry;
import org.infinispan.factories.impl.BasicComponentRegistry;
import org.infinispan.factories.impl.ComponentRef;
import org.infinispan.manager.CacheContainer;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.jboss.logging.Logger;
import org.jgroups.JChannel;
import org.junit.Ignore;
import org.keycloak.common.util.Time;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import org.keycloak.models.sessions.infinispan.util.SessionExpireListeners;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Test concurrent writes to distributed cache with usage of atomic replace
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Ignore
public class DistributedCacheConcurrentWritesTest {

    protected static final Logger logger = Logger.getLogger(DistributedCacheConcurrentWritesTest.class);

    private static final int BATCHES_PER_WORKER = 1000;
    private static final int ITEMS_IN_BATCH = 100;

    public static void main(String[] args) throws Exception {
        BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache1 = createCache("node1");
        BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache2 = createCache("node2");

        ((Cache) cache1).addListener(new SessionExpireListeners("cache1"));
        ((Cache) cache2).addListener(new SessionExpireListeners("cache2"));

        // NOTE: This setup requires infinispan servers to be up and running on localhost:12232 and localhost:13232
//        BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache1 = createRemoteCache("node1");
//        BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache2 = createRemoteCache("node2");

        try {
//            testConcurrentPut(cache1, cache2);

            SessionEntityWrapper<UserSessionEntity> session = createEntityInstance("123");
            SessionEntityWrapper<UserSessionEntity> session2 = createEntityInstance("234");
            SessionEntityWrapper<UserSessionEntity> session3 = createEntityInstance("345");
            SessionEntityWrapper<UserSessionEntity> session4 = createEntityInstance("456");
            SessionEntityWrapper<UserSessionEntity> session5 = createEntityInstance("567");

            cache1.put("123", session, 10, TimeUnit.SECONDS, 9, TimeUnit.SECONDS);
            cache1.put("234", session2, 10, TimeUnit.SECONDS, 9, TimeUnit.SECONDS);
            cache1.put("345", session3, 10, TimeUnit.SECONDS, 9, TimeUnit.SECONDS);
            cache1.put("456", session4, 10, TimeUnit.SECONDS, 9, TimeUnit.SECONDS);
            cache1.put("567", session5, 10, TimeUnit.SECONDS, 9, TimeUnit.SECONDS);

            //pause(8000);
            Time.setOffset(8);

            logger.infof("123 exists: %b, 234 exists: %b, 345 exists: %b, 456 exists: %b, 567 exists: %b", cache1.containsKey("123"), cache1.containsKey("234"), cache1.containsKey("345"), cache1.containsKey("456"), cache1.containsKey("567"));

//            cache2.get("123");
//            cache2.get("234");
//            cache2.get("345");
//            cache2.get("456");
//            cache2.get("567");

            cache1.replace("123", session5, 10, TimeUnit.SECONDS, 5, TimeUnit.SECONDS);
            cache1.replace("234", session2, 10, TimeUnit.SECONDS, 5, TimeUnit.SECONDS);

//            List cacheEntries = (List) CacheDecorators.localCache((Cache<String, SessionEntityWrapper<UserSessionEntity>>) cache1).keySet().stream().filter(key -> key.equals("123"))
//                    .collect(Collectors.toList());

                    //.collect(Collectors.toMap(sessionEntityWrapper -> sessionEntityWrapper.getEntity().getId(), Function.identity()));
                   //.collect(Collectors.toList());

            // pause(3000);
            Time.setOffset(11);

            logger.infof("123 exists: %b, 234 exists: %b, 345 exists: %b, 456 exists: %b, 567 exists: %b", cache1.containsKey("123"), cache1.containsKey("234"), cache1.containsKey("345"), cache1.containsKey("456"), cache1.containsKey("567"));


//            for (int i=0 ; i<1 ; i++) {
//                pause(i, 6000, cache1);
//            }
//
//            logger.info("REPLACING 456");
//            cache1.replace("456", session2, 10, TimeUnit.SECONDS, 5, TimeUnit.SECONDS);
//
//            for (int i=5 ; i<35 ; i++) {
//                pause(i, 1000, cache1);
//            }

            logger.info("FINISH");

        } finally {

            // Kill JVM
            cache1.stop();
            cache2.stop();
            stopMgr(cache1);
            stopMgr(cache2);

            System.out.println("Managers killed");
        }
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ie) {
            throw new RuntimeException(ie);
        }
    }


    private static SessionEntityWrapper<UserSessionEntity> createEntityInstance(String id) {
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

        return new SessionEntityWrapper<>(session);
    }


    // Reproducer for KEYCLOAK-7443 and KEYCLOAK-7489. The infinite loop can happen if cache.replace(key, old, new) is called and entity was removed on one cluster node in the meantime
    private static void testConcurrentPut(BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache1,
                                          BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache2) throws InterruptedException {

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

        System.out.println("Test finished. Took: " + took + " ms. Cache size: " + cache1.size());

        // JGroups statistics
        printStats(cache1);
    }


    private static class Worker extends Thread {

        private final BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache;
        private final int startIndex;

        public Worker(int threadId, BasicCache<String, SessionEntityWrapper<UserSessionEntity>> cache) {
            this.cache = cache;
            this.startIndex = (threadId - 1) * (ITEMS_IN_BATCH * BATCHES_PER_WORKER);
            setName("th-" + threadId);
        }

        @Override
        public void run() {

            for (int page = 0; page < BATCHES_PER_WORKER ; page++) {
                int startPageIndex = startIndex + page * ITEMS_IN_BATCH;

                putItemsClassic(startPageIndex);
                //putItemsAll(startPageIndex);

                System.out.println("Thread " + getName() + ": Saved items from " + startPageIndex + " to " + (startPageIndex + ITEMS_IN_BATCH - 1));
            }
        }


        // put items 1 by 1
        private void putItemsClassic(int startPageIndex) {
            for (int i = startPageIndex ; i < (startPageIndex + ITEMS_IN_BATCH) ; i++) {
                String key = "key-" + startIndex + i;
                SessionEntityWrapper<UserSessionEntity> session = createEntityInstance(key);
                cache.put(key, session);
            }
        }


        // put all items together
        private void putItemsAll(int startPageIndex) {
            Map<String, SessionEntityWrapper<UserSessionEntity>> mapp = new HashMap<>();

            for (int i = startPageIndex ; i < (startPageIndex + ITEMS_IN_BATCH) ; i++) {
                String key = "key-" + startIndex + i;
                SessionEntityWrapper<UserSessionEntity> session = createEntityInstance(key);
                mapp.put(key, session);
            }

            cache.putAll(mapp);
        }
    }


    // Cache creation utils


    public static BasicCache<String, SessionEntityWrapper<UserSessionEntity>> createCache(String nodeName) {
        EmbeddedCacheManager mgr = createManager(nodeName);
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = mgr.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
        return cache;
    }


    public static EmbeddedCacheManager createManager(String nodeName) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        System.setProperty("jgroups.tcp.port", "53715");

        GlobalConfigurationBuilder gcb = new GlobalConfigurationBuilder();
        gcb = gcb.clusteredDefault();
        gcb.transport().clusterName("test-clustering");
        gcb.transport().nodeName(nodeName);

        //gcb.jmx().domain(InfinispanConnectionProvider.JMX_DOMAIN).enable();
        EmbeddedCacheManager cacheManager = new DefaultCacheManager(gcb.build(), false);
        TimeService timeService = new ControlledTimeService();
        replaceComponent(cacheManager,  TimeService.class, timeService, true);
        cacheManager.start();

        ConfigurationBuilder distConfigBuilder = new ConfigurationBuilder();
        distConfigBuilder.clustering().cacheMode(CacheMode.DIST_SYNC);
        distConfigBuilder.clustering().hash().numOwners(1);

        // Disable L1 cache
        distConfigBuilder.clustering().hash().l1().enabled(false);
        Configuration distConfig = distConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, distConfig);

        return cacheManager;
    }


    public static BasicCache<String, SessionEntityWrapper<UserSessionEntity>> createRemoteCache(String nodeName) {
        int port = ("node1".equals(nodeName)) ? 12232 : 13232;

        org.infinispan.client.hotrod.configuration.ConfigurationBuilder builder = new org.infinispan.client.hotrod.configuration.ConfigurationBuilder();
        org.infinispan.client.hotrod.configuration.Configuration cfg = builder
                .addServer().host("localhost").port(port)
                .version(ProtocolVersion.PROTOCOL_VERSION_26)
                .build();
        RemoteCacheManager mgr = new RemoteCacheManager(cfg);
        return mgr.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
    }

    // CLEANUP METHODS

    private static void stopMgr(BasicCache cache) {
        if (cache instanceof Cache) {
            ((Cache) cache).getCacheManager().stop();
        } else {
            ((RemoteCache) cache).getRemoteCacheManager().stop();
        }
    }


    private static void printStats(BasicCache cache) {
        if (cache instanceof Cache) {
            Cache cache1 = (Cache) cache;

            JChannel channel = ((JGroupsTransport)cache1.getAdvancedCache().getRpcManager().getTransport()).getChannel();

            System.out.println("Sent MB: " + channel.getSentBytes() / 1000000 + ", sent messages: " + channel.getSentMessages() + ", received MB: " + channel.getReceivedBytes() / 1000000 +
                    ", received messages: " + channel.getReceivedMessages());
        } else {
            Map<String, String> stats = ((RemoteCache) cache).stats().getStatsMap();
            System.out.println("Stats: " + stats);
        }
    }


    /**
     * Replaces a component in a running cache manager (global component registry)
     *
     * @param cacheMgr       cache in which to replace component
     * @param componentType        component type of which to replace
     * @param replacementComponent new instance
     * @param rewire               if true, ComponentRegistry.rewire() is called after replacing.
     *
     * @return the original component that was replaced
     */
    public static <T> T replaceComponent(EmbeddedCacheManager cacheMgr, Class<T> componentType, T replacementComponent,
                                         boolean rewire) {
        return replaceComponent(cacheMgr, componentType, componentType.getName(), replacementComponent, rewire);
    }

    /**
     * Same as {@link TestingUtil#replaceComponent(CacheContainer, Class, Object, boolean)} except that you can provide
     * an optional name, to replace specifically named components.
     *
     * @param cacheContainer       cache in which to replace component
     * @param componentType        component type of which to replace
     * @param name                 name of the component
     * @param replacementComponent new instance
     * @param rewire               if true, ComponentRegistry.rewire() is called after replacing.
     *
     * @return the original component that was replaced
     */
    public static <T> T replaceComponent(EmbeddedCacheManager cacheMgr, Class<T> componentType, String name, T replacementComponent, boolean rewire) {
        GlobalComponentRegistry cr = cacheMgr.getGlobalComponentRegistry();
        BasicComponentRegistry bcr = cr.getComponent(BasicComponentRegistry.class);
        ComponentRef<T> old = bcr.getComponent(componentType);
        bcr.replaceComponent(name, replacementComponent, true);
        if (rewire) {
            cr.rewire();
            cr.rewireNamedRegistries();
        }
        return old != null ? old.wired() : null;
    }
}
