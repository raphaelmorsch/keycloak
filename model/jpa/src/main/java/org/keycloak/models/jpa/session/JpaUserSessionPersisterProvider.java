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

package org.keycloak.models.jpa.session;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.session.PersistentAuthenticatedClientSessionAdapter;
import org.keycloak.models.session.PersistentClientSessionModel;
import org.keycloak.models.session.PersistentUserSessionAdapter;
import org.keycloak.models.session.PersistentUserSessionModel;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.utils.SessionTimeoutHelper;
import org.keycloak.storage.StorageId;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JpaUserSessionPersisterProvider implements UserSessionPersisterProvider {
    private static final Logger logger = Logger.getLogger(JpaUserSessionPersisterProvider.class);

    private final KeycloakSession session;
    private final EntityManager em;

    public JpaUserSessionPersisterProvider(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    @Override
    public void createUserSession(UserSessionModel userSession, boolean offline) {
        PersistentUserSessionAdapter adapter = new PersistentUserSessionAdapter(userSession);
        PersistentUserSessionModel model = adapter.getUpdatedModel();

        PersistentUserSessionEntity entity = new PersistentUserSessionEntity();
        entity.setUserSessionId(model.getUserSessionId());
        entity.setRealmId(adapter.getRealm().getId());
        entity.setUserId(adapter.getUser().getId());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        entity.setLastSessionRefresh(model.getLastSessionRefresh());
        entity.setData(model.getData());
        em.persist(entity);
        em.flush();
    }

    @Override
    public void createClientSession(AuthenticatedClientSessionModel clientSession, boolean offline) {
        PersistentAuthenticatedClientSessionAdapter adapter = new PersistentAuthenticatedClientSessionAdapter(clientSession);
        PersistentClientSessionModel model = adapter.getUpdatedModel();

        PersistentClientSessionEntity entity = new PersistentClientSessionEntity();
        StorageId clientStorageId = new StorageId(clientSession.getClient().getId());
        if (clientStorageId.isLocal()) {
            entity.setClientId(clientStorageId.getId());
            entity.setClientStorageProvider(PersistentClientSessionEntity.LOCAL);
            entity.setExternalClientId(PersistentClientSessionEntity.LOCAL);

        } else {
            entity.setClientId(PersistentClientSessionEntity.EXTERNAL);
            entity.setClientStorageProvider(clientStorageId.getProviderId());
            entity.setExternalClientId(clientStorageId.getExternalId());
        }
        entity.setTimestamp(clientSession.getTimestamp());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        entity.setUserSessionId(clientSession.getUserSession().getId());
        entity.setData(model.getData());
        em.persist(entity);
        em.flush();
    }

    @Override
    public void removeUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);

        em.createNamedQuery("deleteClientSessionsByUserSession")
                .setParameter("userSessionId", userSessionId)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        PersistentUserSessionEntity sessionEntity = em.find(PersistentUserSessionEntity.class, new PersistentUserSessionEntity.Key(userSessionId, offlineStr));
        if (sessionEntity != null) {
            em.remove(sessionEntity);
            em.flush();
        }
    }

    @Override
    public void removeClientSession(String userSessionId, String clientUUID, boolean offline) {
        String offlineStr = offlineToString(offline);
        StorageId clientStorageId = new StorageId(clientUUID);
        String clientId = PersistentClientSessionEntity.EXTERNAL;
        String clientStorageProvider = PersistentClientSessionEntity.LOCAL;
        String externalId = PersistentClientSessionEntity.LOCAL;
        if (clientStorageId.isLocal()) {
            clientId = clientUUID;
        } else {
            clientStorageProvider = clientStorageId.getProviderId();
            externalId = clientStorageId.getExternalId();

        }
        PersistentClientSessionEntity sessionEntity = em.find(PersistentClientSessionEntity.class, new PersistentClientSessionEntity.Key(userSessionId, clientId, clientStorageProvider, externalId, offlineStr));
        if (sessionEntity != null) {
            em.remove(sessionEntity);

            // Remove userSession if it was last clientSession
            List<PersistentClientSessionEntity> clientSessions = getClientSessionsByUserSession(sessionEntity.getUserSessionId(), offline);
            if (clientSessions.size() == 0) {
                offlineStr = offlineToString(offline);
                PersistentUserSessionEntity userSessionEntity = em.find(PersistentUserSessionEntity.class, new PersistentUserSessionEntity.Key(sessionEntity.getUserSessionId(), offlineStr));
                if (userSessionEntity != null) {
                    em.remove(userSessionEntity);
                }
            }

            em.flush();
        }
    }

    private List<PersistentClientSessionEntity> getClientSessionsByUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);

        TypedQuery<PersistentClientSessionEntity> query = em.createNamedQuery("findClientSessionsByUserSession", PersistentClientSessionEntity.class);
        query.setParameter("userSessionId", userSessionId);
        query.setParameter("offline", offlineStr);
        return query.getResultList();
    }



    @Override
    public void onRealmRemoved(RealmModel realm) {
        int num = em.createNamedQuery("deleteClientSessionsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        num = em.createNamedQuery("deleteUserSessionsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        onClientRemoved(client.getId());
    }

    private void onClientRemoved(String clientUUID) {
        int num = 0;
        StorageId clientStorageId = new StorageId(clientUUID);
        if (clientStorageId.isLocal()) {
            num = em.createNamedQuery("deleteClientSessionsByClient").setParameter("clientId", clientUUID).executeUpdate();
        } else {
            num = em.createNamedQuery("deleteClientSessionsByExternalClient")
                    .setParameter("clientStorageProvider", clientStorageId.getProviderId())
                    .setParameter("externalClientId", clientStorageId.getExternalId())
                    .executeUpdate();
        }

        // TODO:mposolda Run "deleteDetachedUserSessions" separately in dedicated transaction
        //num = em.createNamedQuery("deleteDetachedUserSessions").executeUpdate();
    }

    @Override
    public void onUserRemoved(RealmModel realm, UserModel user) {
        onUserRemoved(realm, user.getId());
    }

    private void onUserRemoved(RealmModel realm, String userId) {
        int num = em.createNamedQuery("deleteClientSessionsByUser").setParameter("userId", userId).executeUpdate();
        num = em.createNamedQuery("deleteUserSessionsByUser").setParameter("userId", userId).executeUpdate();
    }


    @Override
    public void updateLastSessionRefreshes(RealmModel realm, int lastSessionRefresh, Collection<String> userSessionIds, boolean offline) {
        String offlineStr = offlineToString(offline);

        int us = em.createNamedQuery("updateUserSessionLastSessionRefresh")
                .setParameter("lastSessionRefresh", lastSessionRefresh)
                .setParameter("realmId", realm.getId())
                .setParameter("offline", offlineStr)
                .setParameter("userSessionIds", userSessionIds)
                .executeUpdate();

        // TODO:mposolda debug
        logger.infof("Updated lastSessionRefresh of %d user sessions in realm '%s'", us, realm.getName());
    }

    @Override
    public void removeExpired(RealmModel realm) {
        int expiredOffline = Time.currentTime() - realm.getOfflineSessionIdleTimeout() - SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;

        String offlineStr = offlineToString(true);

        // TODO:mposolda: trace
        logger.infof("Trigger removing expired user sessions for realm '%s'", realm.getName());

        int cs = em.createNamedQuery("deleteExpiredClientSessions")
                .setParameter("realmId", realm.getId())
                .setParameter("lastSessionRefresh", expiredOffline)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        int us = em.createNamedQuery("deleteExpiredUserSessions")
                .setParameter("realmId", realm.getId())
                .setParameter("lastSessionRefresh", expiredOffline)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        // TODO:mposolda debug
        logger.infof("Removed %d expired user sessions and %d expired client sessions in realm '%s'", us, cs, realm.getName());

    }

    @Override
    public List<UserSessionModel> loadUserSessions(int firstResult, int maxResults, boolean offline, int lastSessionRefresh, String lastUserSessionId) {
        String offlineStr = offlineToString(offline);

        TypedQuery<PersistentUserSessionEntity> query = em.createNamedQuery("findUserSessions", PersistentUserSessionEntity.class);
        query.setParameter("offline", offlineStr);
        query.setParameter("lastSessionRefresh", lastSessionRefresh);
        query.setParameter("lastSessionId", lastUserSessionId);

        if (firstResult != -1) {
            query.setFirstResult(firstResult);
        }
        if (maxResults != -1) {
            query.setMaxResults(maxResults);
        }

        List<PersistentUserSessionEntity> results = query.getResultList();

        // TODO:mposolda
//        CriteriaBuilder builder = em.getCriteriaBuilder();
//        CriteriaQuery<PersistentUserSessionEntity> queryBuilder = builder.createQuery(PersistentUserSessionEntity.class);
//        Root<PersistentUserSessionEntity> root = queryBuilder.from(PersistentUserSessionEntity.class);
//
//        List<Predicate> predicates = new ArrayList<>();
//        predicates.add(builder.equal(root.get("offline"), offlineStr));
//        queryBuilder.where(predicates.toArray(new Predicate[predicates.size()])).orderBy(builder.asc(root.get("userSessionId")));
//
//        TypedQuery<PersistentUserSessionEntity> query = em.createQuery(queryBuilder);
//
//        if (firstResult != -1) {
//            query.setFirstResult(firstResult);
//        }
//
//        if (maxResults != -1) {
//            query.setMaxResults(maxResults);
//        }
//
//        List<PersistentUserSessionEntity> results = query.getResultList();

        List<UserSessionModel> result = new ArrayList<>();
        List<String> userSessionIds = new ArrayList<>();
        for (PersistentUserSessionEntity entity : results) {
            RealmModel realm = session.realms().getRealm(entity.getRealmId());

            result.add(toAdapter(realm, entity));
            userSessionIds.add(entity.getUserSessionId());
        }

        // TODO:mposolda
//
//        // Update timestamps
//        Query queryUpdateTimestamps = em.createNamedQuery("updateUserSessionsTimestamps");
//        queryUpdateTimestamps.setParameter("offline", offlineStr);
//        queryUpdateTimestamps.setParameter("userSessionIds", userSessionIds);
//        queryUpdateTimestamps.setParameter("lastSessionRefresh", clusterStartupTime);
//        int num = queryUpdateTimestamps.executeUpdate();
//        logger.infof("Count updated: %d", num);

        result.sort(Comparator.comparing(UserSessionModel::getId));

        Set<String> removedClientUUIDs = new HashSet<>();

        if (!userSessionIds.isEmpty()) {
            TypedQuery<PersistentClientSessionEntity> query2 = em.createNamedQuery("findClientSessionsByUserSessions", PersistentClientSessionEntity.class);
            query2.setParameter("userSessionIds", userSessionIds);
            query2.setParameter("offline", offlineStr);
            List<PersistentClientSessionEntity> clientSessions = query2.getResultList();

            // Assume both userSessions and clientSessions ordered by userSessionId
            int j = 0;
            for (UserSessionModel ss : result) {
                PersistentUserSessionAdapter userSession = (PersistentUserSessionAdapter) ss;
                Map<String, AuthenticatedClientSessionModel> currentClientSessions = userSession.getAuthenticatedClientSessions(); // This is empty now and we want to fill it

                boolean next = true;
                while (next && j < clientSessions.size()) {
                    PersistentClientSessionEntity clientSession = clientSessions.get(j);
                    if (clientSession.getUserSessionId().equals(userSession.getId())) {
                        PersistentAuthenticatedClientSessionAdapter clientSessAdapter = toAdapter(userSession.getRealm(), userSession, clientSession);

                        // Case when client was removed in the meantime
                        if (clientSessAdapter.getClient() == null) {
                            removedClientUUIDs.add(clientSession.getClientId());
                        } else {
                            currentClientSessions.put(clientSession.getClientId(), clientSessAdapter);
                        }
                        j++;
                    } else {
                        next = false;
                    }
                }
            }
        }

        for (String clientUUID : removedClientUUIDs) {
            onClientRemoved(clientUUID);
        }

        return result;
    }

    private PersistentUserSessionAdapter toAdapter(RealmModel realm, PersistentUserSessionEntity entity) {
        PersistentUserSessionModel model = new PersistentUserSessionModel();
        model.setUserSessionId(entity.getUserSessionId());
        model.setLastSessionRefresh(entity.getLastSessionRefresh());
        model.setData(entity.getData());
        model.setOffline(offlineFromString(entity.getOffline()));

        Map<String, AuthenticatedClientSessionModel> clientSessions = new HashMap<>();
        return new PersistentUserSessionAdapter(session, model, realm, entity.getUserId(), clientSessions);
    }

    private PersistentAuthenticatedClientSessionAdapter toAdapter(RealmModel realm, PersistentUserSessionAdapter userSession, PersistentClientSessionEntity entity) {
        String clientId = entity.getClientId();
        if (!entity.getExternalClientId().equals("local")) {
            clientId = new StorageId(entity.getClientId(), entity.getExternalClientId()).getId();
        }
        ClientModel client = realm.getClientById(clientId);

        PersistentClientSessionModel model = new PersistentClientSessionModel();
        model.setClientId(clientId);
        model.setUserSessionId(userSession.getId());
        model.setUserId(userSession.getUserId());
        model.setTimestamp(entity.getTimestamp());
        model.setData(entity.getData());
        return new PersistentAuthenticatedClientSessionAdapter(model, realm, client, userSession);
    }

    @Override
    public int getUserSessionsCount(boolean offline) {
        String offlineStr = offlineToString(offline);

        Query query = em.createNamedQuery("findUserSessionsCount");
        query.setParameter("offline", offlineStr);
        Number n = (Number) query.getSingleResult();
        return n.intValue();
    }

    @Override
    public void close() {

    }

    private String offlineToString(boolean offline) {
        return offline ? "1" : "0";
    }

    private boolean offlineFromString(String offlineStr) {
        return "1".equals(offlineStr);
    }
}
