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

package org.keycloak.authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.RealmModel;

/**
 * Resolves set of AuthenticationSelectionOptions
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class AuthenticationSelectionResolver {

    private static final Logger logger = Logger.getLogger(AuthenticationSelectionResolver.class);

    /**
     * This method creates the list of authenticators that is presented to the user. For a required execution, this is
     * only the credentials associated to the authenticator, and for an alternative execution, this is all other alternative
     * executions in the flow, including the credentials.
     * <p>
     * In both cases, the credentials take precedence, with the order selected by the user (or his administrator).
     *
     * @param model The current execution model
     * @return an ordered list of the authentication selection options to present the user.
     */
    static List<AuthenticationSelectionOption> createAuthenticationSelectionList(AuthenticationProcessor processor, AuthenticationExecutionModel model) {
        List<AuthenticationSelectionOption> authenticationSelectionList = new ArrayList<>();

        if (processor.getAuthenticationSession() != null) {
            Map<String, AuthenticationExecutionModel> typeAuthExecMap = new HashMap<>();
            List<AuthenticationExecutionModel> nonCredentialExecutions = new ArrayList<>();

            String topFlowId = getFlowIdOfTheMostTopUsefulFlow(processor, model);

            if (topFlowId == null) {
                addSimpleAuthenticationExecution(processor, model, typeAuthExecMap, nonCredentialExecutions);
            } else {
                addAllExecutionsFromSubflow(processor, topFlowId, typeAuthExecMap, nonCredentialExecutions);
            }
//            if (model.isAlternative()) {
//                //get all alternative executions to be able to list their credentials
//                addAllExecutionsFromSubflow(processor, model.getParentFlow(), typeAuthExecMap, nonCredentialExecutions);
//            } else if (model.isRequired()) {
//                if (!model.isAuthenticatorFlow()) {
//                    addSimpleAuthenticationExecution(processor, model, typeAuthExecMap, nonCredentialExecutions);
//                } else {
//                    // RequiredExecution pointed to a flow, so process it recursively as a flow
//                    addAllExecutionsFromSubflow(processor, model.getFlowId(), typeAuthExecMap, nonCredentialExecutions);
//                }
//            }

            //add credential authenticators in order
            if (processor.getAuthenticationSession().getAuthenticatedUser() != null) {
                List<CredentialModel> credentials = processor.getSession().userCredentialManager()
                        .getStoredCredentials(processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser())
                        .stream()
                        .filter(credential -> typeAuthExecMap.containsKey(credential.getType()))
                        .collect(Collectors.toList());

                authenticationSelectionList = credentials.stream()
                        .map(CredentialModel::getType)
                        .distinct()
                        .map(credentialType -> new AuthenticationSelectionOption(processor.getSession(), typeAuthExecMap.get(credentialType)))
                        .collect(Collectors.toList());
            }

            //add all other authenticators
            for (AuthenticationExecutionModel exec : nonCredentialExecutions) {
                authenticationSelectionList.add(new AuthenticationSelectionOption(processor.getSession(), exec));
            }
        }

        // TODO:mposolda: trace?
        logger.infof("Selections when trying execution '%s' : %s", model.getAuthenticator(), authenticationSelectionList);

        return authenticationSelectionList;
    }


    // TODO:mposolda javadoc
    private static String getFlowIdOfTheMostTopUsefulFlow(AuthenticationProcessor processor, AuthenticationExecutionModel execution) {
        String flowId = null;
        RealmModel realm = processor.getRealm();

        while (true) {
            if (execution.isAlternative()) {
                //get all alternative executions to be able to list their credentials
                flowId = execution.getParentFlow();
            } else if (execution.isRequired()  || execution.isConditional()) {
                if (execution.isAuthenticatorFlow()) {
                    flowId = execution.getFlowId();
                }

                // Find the corresponding execution. If it is 1st execution in the particular subflow, we need to consider parent flow as well
                //AuthenticationFlowModel flow = realm.getAuthenticationFlowById(execution.getParentFlow());
                List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutions(execution.getParentFlow());
                int executionIndex = executions.indexOf(execution);
                if (executionIndex != 0) {
                    return flowId;
                } else {
                    flowId = execution.getParentFlow();
                }
            }

            AuthenticationFlowModel flow = realm.getAuthenticationFlowById(flowId);
            if (flow.isTopLevel()) {
                return flowId;
            }
            execution = realm.getAuthenticationExecutionByFlowId(flowId);
        }
    }


    // Process single authExecution, which does NOT point to authentication flow.
    // Fill the typeAuthExecMap and nonCredentialExecutions accordingly
    private static void addSimpleAuthenticationExecution(AuthenticationProcessor processor, AuthenticationExecutionModel execution, Map<String, AuthenticationExecutionModel> typeAuthExecMap, List<AuthenticationExecutionModel> nonCredentialExecutions) {
        Authenticator localAuthenticator = processor.getSession().getProvider(Authenticator.class, execution.getAuthenticator());
        if (!(localAuthenticator instanceof CredentialValidator)) {
            // Don't add already processed executions
            if (!DefaultAuthenticationFlow.isProcessed(processor, execution)) {
                nonCredentialExecutions.add(execution);
            }
        } else {
            CredentialValidator<?> cv = (CredentialValidator<?>) localAuthenticator;
            typeAuthExecMap.put(cv.getType(processor.getSession()), execution);
        }
    }


    // Return true if at least something was added to any of the list
    private static boolean addAllExecutionsFromSubflow(AuthenticationProcessor processor, String flowId, Map<String, AuthenticationExecutionModel> typeAuthExecMap, List<AuthenticationExecutionModel> nonCredentialExecutions) {
        AuthenticationFlowModel flowModel = processor.getRealm().getAuthenticationFlowById(flowId);
        // TODO:mposolda should rather throw an error?
        if (flowModel == null) return false;
        DefaultAuthenticationFlow flow = new DefaultAuthenticationFlow(processor, flowModel);

        // TODO:mposolda debug or trace
        logger.infof("Going through the flow '%s' for adding executions", flowModel.getAlias());

        List<AuthenticationExecutionModel> executions = processor.getRealm().getAuthenticationExecutions(flowId);

        List<AuthenticationExecutionModel> requiredList = new ArrayList<>();
        List<AuthenticationExecutionModel> alternativeList = new ArrayList<>();
        flow.fillListsOfExecutions(executions, requiredList, alternativeList);

        // If requiredList is not empty, we're going to collect just very first execution from the flow
        if (!requiredList.isEmpty()) {
            AuthenticationExecutionModel requiredExecution = requiredList.stream().filter(ex -> {

                if (ex.isRequired()) return true;

                // For conditional execution, we must check if condition is true. Otherwise return false, which means trying next
                // requiredExecution in the list
                return !flow.isConditionalSubflowDisabled(ex);

            }).findFirst().orElse(null);

            // Not requiredExecution found. Returning false as we did not add any authenticator
            if (requiredExecution == null) return false;

            // Recursively add credentials from required execution
            if (requiredExecution.isAuthenticatorFlow()) {
                return addAllExecutionsFromSubflow(processor, requiredExecution.getFlowId(), typeAuthExecMap, nonCredentialExecutions);
            } else {
                addSimpleAuthenticationExecution(processor, requiredExecution, typeAuthExecMap, nonCredentialExecutions);
                return true;
            }
        } else {
            // We're going through all the alternatives
            boolean anyAdded = false;

            for (AuthenticationExecutionModel execution : alternativeList) {
                if (!execution.isAuthenticatorFlow()) {
                    addSimpleAuthenticationExecution(processor, execution, typeAuthExecMap, nonCredentialExecutions);
                    anyAdded = true;
                } else {
                    anyAdded |= addAllExecutionsFromSubflow(processor, execution.getFlowId(), typeAuthExecMap, nonCredentialExecutions);
                }
            }

            return anyAdded;
        }

    }
}
