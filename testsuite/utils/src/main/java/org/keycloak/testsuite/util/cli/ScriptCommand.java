/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.util.cli;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.mappers.ScriptBasedOIDCProtocolMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ScriptCommand extends AbstractCommand {

    private AtomicInteger userCounter = new AtomicInteger();

    @Override
    public String getName() {
        return "scripts";
    }

    @Override
    public void doRunCommand(KeycloakSession sess) {
        final int count = getIntArg(0);
        final int batchCount = getIntArg(1);
        final int startTime = Time.currentTime();

        int remaining = count;
        int totalInvocations = 0;
        while (remaining > 0) {
            int countOfScriptInvocations = Math.min(batchCount, remaining);
            totalInvocations += countOfScriptInvocations;
            invokeScriptNTimes(totalInvocations, startTime, countOfScriptInvocations);
            remaining = remaining - countOfScriptInvocations;
        }

        // Write some summary
        log.infof("Command finished. Total time of %d sessions creation: %d seconds", totalInvocations,Time.currentTime() - startTime);
    }


    private void invokeScriptNTimes(int totalInvocations, int startTime, final int countOfScriptInvocations) {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            @Override
            public void run(KeycloakSession session) {
                RealmModel realm = session.realms().getRealmByName("script");
                ClientModel testApp = realm.getClientByClientId("account-console");
                UserModel john = session.users().getUserByUsername(realm, "john");
                UserSessionModel userSession = session.sessions().createUserSession(realm, john, john.getUsername(), "127.0.0.2", "form", true, null, null);
                ClientSessionContext clientSessionCtx = getClientSessionCtx(session, realm, testApp, userSession, "email");

                ScriptBasedOIDCProtocolMapper mapper = (ScriptBasedOIDCProtocolMapper)session.getKeycloakSessionFactory().getProviderFactory(ProtocolMapper.class, ScriptBasedOIDCProtocolMapper.PROVIDER_ID);
                ProtocolMapperModel mapperModel = testApp.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, "my-script-mapper");
                for (int i = 0; i < countOfScriptInvocations; i++) {
                    mapper.transformAccessToken(new AccessToken(), mapperModel, session, userSession, clientSessionCtx);
                }
            }

        });

        log.infof("Finished %d script invocations. Time since start: %d seconds", totalInvocations, Time.currentTime() - startTime);
    }

    @Override
    public String printUsage() {
        return super.printUsage() + " <iterations-count> <iterations-count-per-each-transaction>";
    }


    private ClientSessionContext getClientSessionCtx(KeycloakSession session, RealmModel realm, ClientModel client, UserSessionModel userSession, String scopeParam) {
        AuthenticationSessionModel authSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        UserModel user = userSession.getUser();

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setAuthenticatedUser(user);
            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, "https://localhost/auth/realms/test");
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);

            AuthenticationManager.setClientScopesInSession(authSession);
            return TokenManager.attachAuthenticationSession(session, userSession, authSession);
        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
    }
}
