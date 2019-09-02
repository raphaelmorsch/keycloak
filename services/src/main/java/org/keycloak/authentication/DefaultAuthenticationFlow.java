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

package org.keycloak.authentication;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.authenticators.conditional.ConditionalBlockAuthenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class DefaultAuthenticationFlow implements AuthenticationFlow {
    private static final Logger logger = Logger.getLogger(DefaultAuthenticationFlow.class);
    private final List<AuthenticationExecutionModel> executions;
    private final AuthenticationProcessor processor;
    private final AuthenticationFlowModel flow;
    private boolean successful;

    public DefaultAuthenticationFlow(AuthenticationProcessor processor, AuthenticationFlowModel flow) {
        this.processor = processor;
        this.flow = flow;
        this.executions = processor.getRealm().getAuthenticationExecutions(flow.getId());
    }

    protected boolean isProcessed(AuthenticationExecutionModel model) {
        if (model.isDisabled()) return true;
        AuthenticationSessionModel.ExecutionStatus status = processor.getAuthenticationSession().getExecutionStatus().get(model.getId());
        if (status == null) return false;
        return status == AuthenticationSessionModel.ExecutionStatus.SUCCESS || status == AuthenticationSessionModel.ExecutionStatus.SKIPPED
                || status == AuthenticationSessionModel.ExecutionStatus.ATTEMPTED
                || status == AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED;
    }

    protected Authenticator createAuthenticator(AuthenticatorFactory factory) {
        String display = processor.getAuthenticationSession().getAuthNote(OAuth2Constants.DISPLAY);
        if (display == null) return factory.create(processor.getSession());


        if (factory instanceof DisplayTypeAuthenticatorFactory) {
            Authenticator authenticator = ((DisplayTypeAuthenticatorFactory) factory).createDisplay(processor.getSession(), display);
            if (authenticator != null) return authenticator;
        }
        // todo create a provider for handling lack of display support
        if (OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(display)) {
            processor.getAuthenticationSession().removeAuthNote(OAuth2Constants.DISPLAY);
            throw new AuthenticationFlowException(AuthenticationFlowError.DISPLAY_NOT_SUPPORTED,
                    ConsoleDisplayMode.browserContinue(processor.getSession(), processor.getRefreshUrl(true).toString()));
        } else {
            return factory.create(processor.getSession());
        }
    }

    @Override
    public Response processAction(String actionExecution) {
        logger.debugv("processAction: {0}", actionExecution);
        if (actionExecution == null || actionExecution.isEmpty()) {
            throw new AuthenticationFlowException("action is not in current execution", AuthenticationFlowError.INTERNAL_ERROR);
        }
        AuthenticationExecutionModel model = processor.getRealm().getAuthenticationExecutionById(actionExecution);
        if (model == null) {
            throw new AuthenticationFlowException("action is not in current execution", AuthenticationFlowError.INTERNAL_ERROR);
        }

        //TODO check that execution is in current flow tree for security reasons?

        MultivaluedMap<String, String> inputData = processor.getRequest().getDecodedFormParameters();
        String authExecId = inputData.getFirst("authenticationExecution");
        String selectedCredentialId = inputData.getFirst("credentialId");


        //check if the user has selected the "back" option
        if (inputData.containsKey("back")) {
            //If current execution is required, get other required executions in flow, and see if we can return to previous
            if (model.isRequired()) {
                List<AuthenticationExecutionModel> executionsInCurrentFlow = processor.getRealm().getAuthenticationExecutions(model.getParentFlow());

                List<AuthenticationExecutionModel> requiredExecutions = executionsInCurrentFlow.stream().filter(AuthenticationExecutionModel::isRequired)
                    .filter(m -> !isConditionalAuthenticator(m)).collect(Collectors.toList());
                int index = requiredExecutions.indexOf(model);
                //if in a list of required executions, move back to previous if not the first
                if (index > 0) {
                    processor.getAuthenticationSession().getExecutionStatus().remove(requiredExecutions.get(index - 1).getId());
                    Response response = processSingleFlowExecutionModel(requiredExecutions.get(index - 1), null, false);
                    if (response == null) {
                        processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
                        return processFlow();
                    } else return response;
                }
            }
            //Otherwise, go up to the parent of the current flow, if one exists
            if (!processor.getRealm().getAuthenticationFlowById(model.getParentFlow()).isTopLevel()) {
                AuthenticationExecutionModel currentFlow = processor.getRealm().getAuthenticationExecutionByFlowId(model.getParentFlow());
                List<AuthenticationExecutionModel> parentFlowExecutions = processor.getRealm().getAuthenticationExecutions(currentFlow.getParentFlow());
                //Clear all execution statuses of executions in parent flow
                for (AuthenticationExecutionModel execution : parentFlowExecutions) {
                    processor.getAuthenticationSession().getExecutionStatus().remove(execution.getId());
                }
                return processFlow();
            }
        }

        // check if the user has switched to a new authentication execution, and if so switch to it.
        if (authExecId != null && !authExecId.isEmpty()) {
            model = processor.getRealm().getAuthenticationExecutionById(authExecId);
            Response response = processSingleFlowExecutionModel(model, selectedCredentialId, false);
            if (response == null) {
                processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
                return processFlow();
            } else return response;
        }

        AuthenticatorFactory factory = getAuthenticatorFactory(model);
        Authenticator authenticator = createAuthenticator(factory);
        AuthenticationProcessor.Result result = processor.createAuthenticatorContext(model, authenticator, executions);
        result.setAuthenticationSelections(createAuthenticationSelectionList(model));

        result.setSelectedCredentialId(selectedCredentialId);

        logger.debugv("action: {0}", model.getAuthenticator());
        authenticator.action(result);
        Response response = processResult(result, true);
        if (response == null) {
            processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
            return processFlow();
        } else return response;
    }

    @Override
    public Response processFlow() {
        logger.debug("processFlow");

        //separate flow elements into required and alternative elements
        List<AuthenticationExecutionModel> conditionalList = new ArrayList<>();
        List<AuthenticationExecutionModel> requiredList = new ArrayList<>();
        List<AuthenticationExecutionModel> alternativeList = new ArrayList<>();

        for (AuthenticationExecutionModel execution : executions) {
            if (isConditionalAuthenticator(execution)) {
                conditionalList.add(execution);
            } else if (execution.isRequired() || execution.isOptional()) {
                requiredList.add(execution);
            } else if (execution.isAlternative()) {
                alternativeList.add(execution);
            }
        }

        // Conditionals should be executed without considering SUCCESS/FAILED status
        // If condition is matched, the execution of the flow goes on
        // If condition is not matched, simply stop processing this flow and go on processing parent flow
        if (flowIsOptional() && (conditionalList.isEmpty() || conditionalList.stream().anyMatch(this::conditionalNotMatched))) {
            successful = true;
            return null;
        }

        //handle required elements : all required elements need to be executed
        boolean requiredElementsSuccessful = true;
        for (AuthenticationExecutionModel required : requiredList) {
            Response response = processSingleFlowExecutionModel(required, null, true);
            requiredElementsSuccessful &= processor.isSuccessful(required);
            if (response == null) {
                continue;
            }
            return response;
        }

        //Evaluate alternative elements only if there are no required elements
        if (requiredList.isEmpty()) {
            //check if an alternative is already successful, in case we are returning in the flow after an action
            if (alternativeList.stream().anyMatch(processor::isSuccessful)) {
                successful = true;
                return null;
            }

            //handle alternative elements: the first alternative element to be satisfied is enough
            for (AuthenticationExecutionModel alternative : alternativeList) {
                try {
                    Response response = processSingleFlowExecutionModel(alternative, null, true);
                    if (response != null) {
                        return response;
                    }
                    if (processor.isSuccessful(alternative)) {
                        successful = true;
                        return null;
                    }
                } catch (AuthenticationFlowException afe) {
                    processor.getAuthenticationSession().setExecutionStatus(alternative.getId(), AuthenticationSessionModel.ExecutionStatus.ATTEMPTED);
                }
            }
        } else {
            successful = requiredElementsSuccessful;
        }
        return null;
    }

    private boolean flowIsOptional() {
        AuthenticationExecutionModel flowModel = processor.getRealm().getAuthenticationExecutionById(flow.getId());
        return flowModel!=null && flowModel.isOptional();
    }

    private boolean isConditionalAuthenticator(AuthenticationExecutionModel model) {
        return !model.isAuthenticatorFlow() && model.getAuthenticator() != null && createAuthenticator(getAuthenticatorFactory(model)) instanceof ConditionalBlockAuthenticator;
    }

    private AuthenticatorFactory getAuthenticatorFactory(AuthenticationExecutionModel model) {
        AuthenticatorFactory factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
        }
        return factory;
    }

    private boolean conditionalNotMatched(AuthenticationExecutionModel model) {
        AuthenticatorFactory factory = getAuthenticatorFactory(model);
        ConditionalBlockAuthenticator authenticator = (ConditionalBlockAuthenticator) createAuthenticator(factory);
        AuthenticationProcessor.Result context = processor.createAuthenticatorContext(model, authenticator, executions);

        return !authenticator.matchCondition(context);
    }

    private Response processSingleFlowExecutionModel(AuthenticationExecutionModel model, String selectedCredentialId, boolean calledFromFlow) {
        logger.debugv("check execution: {0} requirement: {1}", model.getAuthenticator(), model.getRequirement());

        if (isProcessed(model)) {
            logger.debug("execution is processed");
            return null;
        }
        //handle case where execution is a flow
        if (model.isAuthenticatorFlow()) {
            logger.debug("execution is flow");
            AuthenticationFlow authenticationFlow = processor.createFlowExecution(model.getFlowId(), model);
            Response flowChallenge = authenticationFlow.processFlow();
            if (flowChallenge == null) {
                if (authenticationFlow.isSuccessful()) {
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);
                } else {
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.FAILED);
                }
                return null;
            } else {
                processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return flowChallenge;
            }
        }
        //handle normal execution case
        AuthenticatorFactory factory = getAuthenticatorFactory(model);
        Authenticator authenticator = createAuthenticator(factory);
        logger.debugv("authenticator: {0}", factory.getId());
        UserModel authUser = processor.getAuthenticationSession().getAuthenticatedUser();

        //If executions are alternative, get the actual execution to show based on user preference
        List<AuthenticationSelectionOption> selectionOptions = createAuthenticationSelectionList(model);
        if (!selectionOptions.isEmpty() && calledFromFlow) {
            model = selectionOptions.stream().filter(aso -> !aso.getAuthenticationExecution().isAuthenticatorFlow()).findFirst().get().getAuthenticationExecution();
            factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
            if (factory == null) {
                throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
            }
            authenticator = createAuthenticator(factory);
        }
        AuthenticationProcessor.Result context = processor.createAuthenticatorContext(model, authenticator, executions);
        context.setAuthenticationSelections(selectionOptions);
        if (selectedCredentialId != null) {
            context.setSelectedCredentialId(selectedCredentialId);
        }

        if (authenticator.requiresUser()) {
            if (authUser == null) {
                throw new AuthenticationFlowException("authenticator: " + factory.getId(), AuthenticationFlowError.UNKNOWN_USER);
            }
            if (!authenticator.configuredFor(processor.getSession(), processor.getRealm(), authUser)) {
                if (factory.isUserSetupAllowed()) {
                    logger.debugv("authenticator SETUP_REQUIRED: {0}", factory.getId());
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED);
                    authenticator.setRequiredActions(processor.getSession(), processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser());
                    return null;
                } else {
                    throw new AuthenticationFlowException(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
                }
            }
        }
        logger.debugv("invoke authenticator.authenticate: {0}", factory.getId());
        authenticator.authenticate(context);
        return processResult(context, false);
    }

    private List<AuthenticationSelectionOption> createAuthenticationSelectionList(AuthenticationExecutionModel model) {
        List<AuthenticationSelectionOption> authenticationSelectionList = new ArrayList<>();
        if (processor.getAuthenticationSession() != null) {
            Map<String, AuthenticationExecutionModel> typeAuthExecMap = new HashMap<>();
            List<AuthenticationExecutionModel> nonCredentialExecutions = new ArrayList<>();
            if (model.isAlternative()) {
                //get all alternative executions to be able to list their credentials
                List<AuthenticationExecutionModel> alternativeExecutions = processor.getRealm().getAuthenticationExecutions(model.getParentFlow())
                        .stream().filter(AuthenticationExecutionModel::isAlternative).collect(Collectors.toList());
                for (AuthenticationExecutionModel execution : alternativeExecutions) {
                    if (!execution.isAuthenticatorFlow()) {
                        Authenticator localAuthenticator = processor.getSession().getProvider(Authenticator.class, execution.getAuthenticator());
                        if (!(localAuthenticator instanceof CredentialValidator)) {
                            nonCredentialExecutions.add(execution);
                            continue;
                        }
                        CredentialValidator<?> cv = (CredentialValidator<?>) localAuthenticator;
                        typeAuthExecMap.put(cv.getType(processor.getSession()), execution);
                    }
                }
            } else if (model.isRequired() && ! model.isAuthenticatorFlow()) {
                //only get current credentials
                Authenticator authenticator = processor.getSession().getProvider(Authenticator.class, model.getAuthenticator());
                if (authenticator instanceof CredentialValidator) {
                    typeAuthExecMap.put(((CredentialValidator<?>) authenticator).getType(processor.getSession()), model);
                }
            }

            if (processor.getAuthenticationSession().getAuthenticatedUser() != null) {
                List<CredentialModel> credentials = processor.getSession().userCredentialManager()
                        .getStoredCredentials(processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser())
                        .stream()
                        .filter(credential -> typeAuthExecMap.containsKey(credential.getType()))
                        .collect(Collectors.toList());

                MultivaluedMap<String, AuthenticationSelectionOption> countAuthSelections = new MultivaluedHashMap<>();

                for (CredentialModel credential : credentials) {
                    AuthenticationSelectionOption authSel = new AuthenticationSelectionOption(typeAuthExecMap.get(credential.getType()), credential);
                    authenticationSelectionList.add(authSel);
                    countAuthSelections.add(credential.getType(), authSel);
                }
                for(Entry<String, List<AuthenticationSelectionOption>> entry : countAuthSelections.entrySet()) {
                    if (entry.getValue().size() == 1) {
                        entry.getValue().get(0).setShowCredentialName(false);
                    }
                }
                //don't show credential type if there's only a single type in the list
                if (countAuthSelections.keySet().size() == 1 && nonCredentialExecutions.isEmpty()) {
                    for (AuthenticationSelectionOption so : authenticationSelectionList) {
                        so.setShowCredentialType(false);
                    }
                }
            }
            for (AuthenticationExecutionModel exec : nonCredentialExecutions) {
                authenticationSelectionList.add(new AuthenticationSelectionOption(exec));
            }
        }
        return authenticationSelectionList;
    }


    public Response processResult(AuthenticationProcessor.Result result, boolean isAction) {
        AuthenticationExecutionModel execution = result.getExecution();
        FlowStatus status = result.getStatus();
        switch (status) {
            case SUCCESS:
                logger.debugv("authenticator SUCCESS: {0}", execution.getAuthenticator());
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);
                return null;
            case FAILED:
                logger.debugv("authenticator FAILED: {0}", execution.getAuthenticator());
                processor.logFailure();
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.FAILED);
                if (result.getChallenge() != null) {
                    return sendChallenge(result, execution);
                }
                throw new AuthenticationFlowException(result.getError());
            case FORK:
                logger.debugv("reset browser login from authenticator: {0}", execution.getAuthenticator());
                processor.getAuthenticationSession().setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, execution.getId());
                throw new ForkFlowException(result.getSuccessMessage(), result.getErrorMessage());
            case FORCE_CHALLENGE:
            case CHALLENGE:
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return sendChallenge(result, execution);
            case FAILURE_CHALLENGE:
                logger.debugv("authenticator FAILURE_CHALLENGE: {0}", execution.getAuthenticator());
                processor.logFailure();
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return sendChallenge(result, execution);
            case ATTEMPTED:
                logger.debugv("authenticator ATTEMPTED: {0}", execution.getAuthenticator());
                if (execution.getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_CREDENTIALS);
                }
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.ATTEMPTED);
                return null;
            case FLOW_RESET:
                processor.resetFlow();
                return processor.authenticate();
            default:
                logger.debugv("authenticator INTERNAL_ERROR: {0}", execution.getAuthenticator());
                ServicesLogger.LOGGER.unknownResultStatus();
                throw new AuthenticationFlowException(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    public Response sendChallenge(AuthenticationProcessor.Result result, AuthenticationExecutionModel execution) {
        processor.getAuthenticationSession().setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, execution.getId());
        return result.getChallenge();
    }

    @Override
    public boolean isSuccessful() {
        return successful;
    }
}
