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

package org.keycloak.examples.rest;

import java.util.Date;

import org.infinispan.Cache;
import org.infinispan.notifications.Listener;
import org.infinispan.notifications.cachelistener.annotation.CacheEntriesEvicted;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryCreated;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryExpired;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryInvalidated;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryModified;
import org.infinispan.notifications.cachelistener.annotation.CacheEntryRemoved;
import org.infinispan.notifications.cachelistener.event.CacheEntriesEvictedEvent;
import org.infinispan.notifications.cachelistener.event.CacheEntryCreatedEvent;
import org.infinispan.notifications.cachelistener.event.CacheEntryExpiredEvent;
import org.infinispan.notifications.cachelistener.event.CacheEntryInvalidatedEvent;
import org.infinispan.notifications.cachelistener.event.CacheEntryModifiedEvent;
import org.infinispan.notifications.cachelistener.event.CacheEntryRemovedEvent;
import org.jboss.logging.Logger;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class HelloResourceProvider implements RealmResourceProvider {

    private KeycloakSession session;

    private static final Logger LOG = Logger.getLogger(HelloResourceProvider.class);

    private volatile boolean cacheInitialized = false;

    private static final Object lock = new Object();

    public HelloResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Produces("text/plain; charset=utf-8")
    public String get() {
        String name = session.getContext().getRealm().getDisplayName();
        if (name == null) {
            name = session.getContext().getRealm().getName();
        }

        if (!cacheInitialized) {
            synchronized (lock) {
                if (!cacheInitialized) {
                    InfinispanConnectionProvider prov = session.getProvider(InfinispanConnectionProvider.class);
                    Cache sessionsCache = prov.getCache("sessions");

                    sessionsCache.addListener(new CacheListener());

                    LOG.info("Cache listeners initialized");
                }
            }
        }
        return "Hello " + name;


    }

    @Listener
    public static class CacheListener {

        @CacheEntryCreated
        public void created(CacheEntryCreatedEvent<String, Object> event) {
            if (!event.isPre()) {
                // TODO: Debug or trace?
                LOG.infof("Session created.  SessionID: " + event.getKey());
            }
        }

        @CacheEntryModified
        public void modified(CacheEntryModifiedEvent<String, Object> event) {
            if (!event.isPre()) {
                // TODO: Debug or trace?
                LOG.infof("Session updated.  SessionID: " + event.getKey());
            }
        }

        @CacheEntryRemoved
        public void removed(CacheEntryRemovedEvent<String, Object> event) {
            if (!event.isPre()) {
                // TODO: Debug or trace?
                LOG.infof("Session removed.  SessionID: " + event.getKey());
            }
        }

        @CacheEntryExpired
        public void expired(CacheEntryExpiredEvent<String, Object> event) {
            if (!event.isPre()) {
                // TODO: Debug or trace?
                LOG.infof("Session expired.  SessionID: " + event.getKey());
            }
        }

    }


    @Override
    public void close() {
    }

}
