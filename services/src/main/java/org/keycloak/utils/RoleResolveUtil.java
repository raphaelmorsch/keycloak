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

package org.keycloak.utils;

import java.util.Map;
import java.util.Set;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.DefaultClientSessionContext;

/**
 * Helper class to ensure that composite roles are loaded just once per request. Then all underlying protocolMappers can consume them.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RoleResolveUtil {

    private static final String RESOLVED_ROLES_ATTR = "RESOLVED_ROLES";


    public static AccessToken.Access getResolvedRealmRoles(KeycloakSession session, DefaultClientSessionContext clientSessionCtx) {
        return getAllCompositeRoles(session, clientSessionCtx).getRealmAccess();
    }


    public static Map<String, AccessToken.Access> getResolvedClientRoles(KeycloakSession session, DefaultClientSessionContext clientSessionCtx) {
        return getAllCompositeRoles(session, clientSessionCtx).getResourceAccess();
    }


    private static AccessToken getAllCompositeRoles(KeycloakSession session, DefaultClientSessionContext clientSessionCtx) {
        AccessToken resolvedRoles = session.getAttribute(RESOLVED_ROLES_ATTR, AccessToken.class);
        if (resolvedRoles == null) {
            resolvedRoles = loadCompositeRoles(session, clientSessionCtx);
            session.setAttribute(RESOLVED_ROLES_ATTR, resolvedRoles);
        }

        return resolvedRoles;
    }


    private static AccessToken loadCompositeRoles(KeycloakSession session, DefaultClientSessionContext clientSessionCtx) {
        Set<RoleModel> requestedRoles = clientSessionCtx.getRoles();
        AccessToken token = new AccessToken();
        for (RoleModel role : requestedRoles) {
            addComposites(token, role);
        }
        return token;
    }


    private static void addComposites(AccessToken token, RoleModel role) {
        AccessToken.Access access = null;
        if (role.getContainer() instanceof RealmModel) {
            access = token.getRealmAccess();
            if (token.getRealmAccess() == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            } else if (token.getRealmAccess().getRoles() != null && token.getRealmAccess().isUserInRole(role.getName()))
                return;

        } else {
            ClientModel app = (ClientModel) role.getContainer();
            access = token.getResourceAccess(app.getClientId());
            if (access == null) {
                access = token.addAccess(app.getClientId());
                if (app.isSurrogateAuthRequired()) access.verifyCaller(true);
            } else if (access.isUserInRole(role.getName())) return;

        }
        access.addRole(role.getName());
        if (!role.isComposite()) return;

        for (RoleModel composite : role.getComposites()) {
            addComposites(token, composite);
        }

    }

}
