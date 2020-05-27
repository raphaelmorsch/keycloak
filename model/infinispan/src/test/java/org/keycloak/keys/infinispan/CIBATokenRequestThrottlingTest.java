/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.keys.infinispan;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.infinispan.Cache;
import org.infinispan.configuration.cache.Configuration;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CIBATokenRequestThrottlingTest {

    protected static final Logger logger = Logger.getLogger(CIBATokenRequestThrottlingTest.class);

    // Just to test that reading from multiple threads works as expected
    private static final int THREADS_COUNT = 5;

    // Number of reads, which every thread will try
    private static final int ATTEMPTS = 10;

    // Interval, which every thread spent among reads. The life-time of every thread will be (INTERVAL_READ_IN_SECONDS * ATTEMPTS) seconds
    private static final int INTERVAL_READ_SECONDS = 1;

    // Allowed interval. This is what is effectively used in the CIBA backchannel authentication response as interval
    private static final int INTERVAL_SECONDS = 5;

    private static final int EXPECTED_SUCCESS_REQUESTS = (ATTEMPTS * INTERVAL_READ_SECONDS) / INTERVAL_SECONDS;

    private static final int EXPECTED_FAILURE_REQUESTS = (ATTEMPTS * THREADS_COUNT) - EXPECTED_SUCCESS_REQUESTS;

    private Cache<String, String> cibaCache = getLocalCache();
    //private Cache<String, String> cibaCache = getClusteredCache();

    @Test
    public void testCIbaTokenRequestThrottling() throws Exception {
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        Runnable r = () -> {
            for (int i = 0; i < ATTEMPTS; i++) {
                try {
                    Thread.sleep(INTERVAL_READ_SECONDS * 1000);
                } catch (InterruptedException t) {
                    throw new RuntimeException(t);
                }

                boolean permitted = checkIfClientPermitted("auth_req_id", INTERVAL_SECONDS);
                if (permitted) {
                    successCount.incrementAndGet();
                } else {
                    failureCount.incrementAndGet();
                }

                logger.info(i + ":" + permitted);
            }
        };

        List<Thread> threads = new ArrayList<>();
        for (int i=0 ; i<THREADS_COUNT ; i++) {
            threads.add(new Thread(r));
        }

        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join();
        }

        logger.infof("Success count: %d, Failures count: %d", successCount.get(), failureCount.get());
        Assert.assertEquals(EXPECTED_SUCCESS_REQUESTS, successCount.get());
        Assert.assertEquals(EXPECTED_FAILURE_REQUESTS, failureCount.get());
    }

    /**
     * If this returns false, it means that client sent the TokenRequest too early after the previous request and we should reject client request
     */
    private boolean checkIfClientPermitted(String key, int intervalSeconds) {
        // The item should be expired after intervalSeconds seconds.
        String returned = cibaCache.putIfAbsent(key, key, intervalSeconds, TimeUnit.SECONDS);

        // We failed to put the stuff to the cache. Something is already present. This means that client sent the TokenRequest too early and we should reject
        // client request
        return (returned == null);
    }

    protected Cache<String, String> getLocalCache() {
        GlobalConfigurationBuilder gcb = new GlobalConfigurationBuilder();
        gcb.globalJmxStatistics().allowDuplicateDomains(true).enabled(true);

        final DefaultCacheManager cacheManager = new DefaultCacheManager(gcb.build());

        ConfigurationBuilder cb = new ConfigurationBuilder();
//        cb.jmxStatistics().enabled(true);
        Configuration cfg = cb.build();

        cacheManager.defineConfiguration("ciba-throttling", cfg);
        return cacheManager.getCache("ciba-throttling");
    }

//    public static Cache<String, String> getClusteredCache() {
//        // Used 2 caches just to simulate cluster
//        EmbeddedCacheManager mgr1 = createManager("node1");
//        Cache<String, String> cache1 = mgr1.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
//
//        EmbeddedCacheManager mgr2 = createManager("node2");
//        Cache<String, String> cache2 = mgr2.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
//        return cache1;
//    }
//
//    public static EmbeddedCacheManager createManager(String nodeName) {
//        System.setProperty("java.net.preferIPv4Stack", "true");
//        System.setProperty("jgroups.tcp.port", "53715");
//        GlobalConfigurationBuilder gcb = new GlobalConfigurationBuilder();
//
//        boolean clustered = true;
//        boolean allowDuplicateJMXDomains = true;
//
//        if (clustered) {
//            gcb = gcb.clusteredDefault();
//            gcb.transport().clusterName("test-clustering");
//            gcb.transport().nodeName(nodeName);
//        }
//        gcb.globalJmxStatistics().allowDuplicateDomains(allowDuplicateJMXDomains);
//
//        EmbeddedCacheManager cacheManager = new DefaultCacheManager(gcb.build());
//
//
//        ConfigurationBuilder distConfigBuilder = new ConfigurationBuilder();
//        if (clustered) {
//            distConfigBuilder.clustering().cacheMode(CacheMode.DIST_SYNC);
//            distConfigBuilder.clustering().hash().numOwners(1);
//
//            // Disable L1 cache
//            //distConfigBuilder.clustering().hash().l1().enabled(false);
//        }
//        Configuration distConfig = distConfigBuilder.build();
//
//        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, distConfig);
//        return cacheManager;
//
//    }
}
