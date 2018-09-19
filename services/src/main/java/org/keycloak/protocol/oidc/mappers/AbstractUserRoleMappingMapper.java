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

package org.keycloak.protocol.oidc.mappers;

import org.keycloak.models.GroupModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.representations.IDToken;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Base class for mapping of user role mappings to an ID and Access Token claim.
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
abstract class AbstractUserRoleMappingMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    /**
     * Returns a stream with roles that come from:
     * <ul>
     * <li>Direct assignment of the role to the user</li>
     * <li>Direct assignment of the role to any group of the user or any of its parent group</li>
     * <li>Composite roles are expanded recursively, the composite role itself is also contained in the returned stream</li>
     * </ul>
     * @param user User to enumerate the roles for
     * @return
     */
    public static Stream<RoleModel> getAllUserRolesStream(UserModel user) {
        return Stream.concat(
          user.getRoleMappings().stream(),
          user.getGroups().stream()
            .flatMap(g -> groupAndItsParentsStream(g))
            .flatMap(g -> g.getRoleMappings().stream()))
          .flatMap(RoleUtils::expandCompositeRolesStream);
    }

    /**
     * Returns stream of the given group and its parents (recursively).
     * @param group
     * @return
     */
    private static Stream<GroupModel> groupAndItsParentsStream(GroupModel group) {
        Stream.Builder<GroupModel> sb = Stream.builder();
        while (group != null) {
            sb.add(group);
            group = group.getParent();
        }
        return sb.build();
    }

    /**
     * Retrieves all roles of the current user based on direct roles set to the user, its groups and their parent groups.
     * Then it recursively expands all composite roles, and restricts according to the given predicate {@code restriction}.
     * If the current client sessions is restricted (i.e. no client found in active user session has full scope allowed),
     * the final list of roles is also restricted by the client scope. Finally, the list is mapped to the token into
     * a claim.
     *
     * @param token
     * @param mappingModel
     * @param userSession
     * @param restriction
     * @param prefix
     */
    protected static void setClaim(IDToken token, ProtocolMapperModel mappingModel, Set<String> rolesToAdd,
                                   String clientId, String prefix) {

        Set<String> realmRoleNames;
        if (prefix != null && !prefix.isEmpty()) {
            realmRoleNames = rolesToAdd.stream()
                    .map(roleName -> prefix + roleName)
                    .collect(Collectors.toSet());
        } else {
            realmRoleNames = rolesToAdd;
        }

        Object claimValue = realmRoleNames;

        boolean multiValued = "true".equals(mappingModel.getConfig().get(ProtocolMapperUtils.MULTIVALUED));
        if (!multiValued) {
            claimValue = realmRoleNames.toString();
        }

        //OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
        mapClaim(token, mappingModel, claimValue, clientId);
    }


    private static void mapClaim(IDToken token, ProtocolMapperModel mappingModel, Object attributeValue, String clientId) {
        attributeValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, attributeValue);
        if (attributeValue == null) return;

        String protocolClaim = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        if (protocolClaim == null) {
            return;
        }



        List<String> split = OIDCAttributeMapperHelper.splitClaimPath(protocolClaim);
        final int length = split.size();
        int i = 0;
        Map<String, Object> jsonObject = token.getOtherClaims();
        for (String component : split) {

            if ("${client_id}".equals(component) && clientId != null) {
                component = clientId;
            }

            i++;
            if (i == length) {
                // Case when we want to add to existing set of roles
                Object last = jsonObject.get(component);
                if (last != null && last instanceof Collection && attributeValue instanceof Collection) {
                    ((Collection) last).addAll((Collection) attributeValue);
                } else {
                    jsonObject.put(component, attributeValue);
                }

            } else {
                Map<String, Object> nested = (Map<String, Object>)jsonObject.get(component);

                if (nested == null) {
                    nested = new HashMap<>();
                    jsonObject.put(component, nested);
                }

                jsonObject = nested;
            }
        }
    }
}
