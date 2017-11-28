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

package org.keycloak.sessions;

import java.util.Map;
import java.util.Set;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Encapsulates data related to one authentication browser session.
 *
 * It's scoped to the whole browser (EG. if there are multiple browser tabs opened with the login screen, the
 * AuthenticationSessionModel encapsulates data related to all those browser tabs).
 *
 * The single browser tab is represented by {@link AuthenticationSessionClientModel}
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface AuthenticationSessionModel {

    String getId();
    RealmModel getRealm();


    /**
     * Key is client UUID. Value is AuthenticationSessionClientModel related to the given client
     *
     * @return map with data of all the client authentication sessions in all browser tabs.
     */
    Map<String, AuthenticationSessionClientModel> getClientSessions();

    AuthenticationSessionClientModel getClientSession(String clientUUID);

    /**
     * Create new clientSession for the particular client and attach to this authenticationSession.
     * If there is already existing clientSession for this client, then rewrite the existing session.
     *
     * @param client
     * @return
     */
    AuthenticationSessionClientModel createClientSession(ClientModel client);

    int getTimestamp();
    void setTimestamp(int timestamp);

    String getAction();
    void setAction(String action);

    Map<String, CommonClientSessionModel.ExecutionStatus> getExecutionStatus();
    void setExecutionStatus(String authenticator, CommonClientSessionModel.ExecutionStatus status);
    void clearExecutionStatus();
    UserModel getAuthenticatedUser();
    void setAuthenticatedUser(UserModel user);

    /**
     * Required actions that are attached to this client session.
     *
     * @return
     */
    Set<String> getRequiredActions();

    void addRequiredAction(String action);

    void removeRequiredAction(String action);

    void addRequiredAction(UserModel.RequiredAction action);

    void removeRequiredAction(UserModel.RequiredAction action);


    /**
     *  Sets the given user session note to the given value. User session notes are notes
     *  you want be applied to the UserSessionModel when the client session is attached to it.
     */
    void setUserSessionNote(String name, String value);
    /**
     *  Retrieves value of given user session note. User session notes are notes
     *  you want be applied to the UserSessionModel when the client session is attached to it.
     */
    Map<String, String> getUserSessionNotes();
    /**
     *  Clears all user session notes. User session notes are notes
     *  you want be applied to the UserSessionModel when the client session is attached to it.
     */
    void clearUserSessionNotes();

    /**
     *  Retrieves value of the given authentication note to the given value. Authentication notes are notes
     *  used typically by authenticators and authentication flows. They are cleared when
     *  authentication session is restarted
     */
    String getAuthNote(String name);
    /**
     *  Sets the given authentication note to the given value. Authentication notes are notes
     *  used typically by authenticators and authentication flows. They are cleared when
     *  authentication session is restarted
     */
    void setAuthNote(String name, String value);
    /**
     *  Removes the given authentication note. Authentication notes are notes
     *  used typically by authenticators and authentication flows. They are cleared when
     *  authentication session is restarted
     */
    void removeAuthNote(String name);
    /**
     *  Clears all authentication note. Authentication notes are notes
     *  used typically by authenticators and authentication flows. They are cleared when
     *  authentication session is restarted
     */
    void clearAuthNotes();

    // Will completely restart whole state of authentication session. It will just keep same ID. It will setup it with provided realm.
    void restartSession(RealmModel realm);

    /**
     * Restarts the authentication state of this authentication session (Executions, authNotes etc). It doesn't restart client sessions
     */
    void restartAuthentication();
}
