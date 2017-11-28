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

package org.keycloak.sessions;

import java.util.Map;

import org.keycloak.models.ClientModel;

/**
 * Encapsulates data related to single client within {@link AuthenticationSessionModel}. Typically single browser tab.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface AuthenticationSessionClientModel extends CommonClientSessionModel {

    AuthenticationSessionModel getAuthenticationSession();


    ClientModel getClient();

    /**
     *  Retrieves value of the given client note to the given value. Client notes are notes
     *  specific to client protocol. They are NOT cleared when authentication session is restarted.
     */
    String getClientNote(String name);
    /**
     *  Sets the given client note to the given value. Client notes are notes
     *  specific to client protocol. They are NOT cleared when authentication session is restarted.
     */
    void setClientNote(String name, String value);
    /**
     *  Removes the given client note. Client notes are notes
     *  specific to client protocol. They are NOT cleared when authentication session is restarted.
     */
    void removeClientNote(String name);
    /**
     *  Retrieves the (name, value) map of client notes. Client notes are notes
     *  specific to client protocol. They are NOT cleared when authentication session is restarted.
     */
    Map<String, String> getClientNotes();
    /**
     *  Clears all client notes. Client notes are notes
     *  specific to client protocol. They are NOT cleared when authentication session is restarted.
     */
    void clearClientNotes();

    void updateClient(ClientModel client);
}
