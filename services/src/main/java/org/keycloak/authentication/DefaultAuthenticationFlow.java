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
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class DefaultAuthenticationFlow implements AuthenticationFlow {
    private static final Logger logger = Logger.getLogger(DefaultAuthenticationFlow.class);
    private final List<AuthenticationExecutionModel> executions;
    private final AuthenticationProcessor processor;
    private final AuthenticationFlowModel flow; //basically useless, either remove from here in the future, or find a use for it.
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

        //TODO check that execution is in current flow tree for security reasons? Would be far less expensive then the old "go through all" approach,

        // check if the user has switched to a new authentication execution, and if so switch to it.
        MultivaluedMap<String, String> inputData = processor.getRequest().getDecodedFormParameters();
        String authExecId = inputData.getFirst("authenticationExecution");
        String selectedCredentialId = inputData.getFirst("credentialId");
        if (authExecId != null && !authExecId.isEmpty()) {
            model = processor.getRealm().getAuthenticationExecutionById(authExecId);
            Response response = processSingleFlowExecutionModel(model, selectedCredentialId);
            if (response == null) {
                processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
                return processFlow();
            } else return response;
        }

        AuthenticatorFactory factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
        }
        Authenticator authenticator = createAuthenticator(factory);
        AuthenticationProcessor.Result result = processor.createAuthenticatorContext(model, authenticator, executions);
        createAuthentictorCredentialMap(model, result);
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
        List<AuthenticationExecutionModel> requiredList = new ArrayList<>();
        List<AuthenticationExecutionModel> alternativeList = new ArrayList<>();

        for (AuthenticationExecutionModel execution : executions) {
            if (execution.isRequired() /*|| execution.isOptional()*/) {
                //TODO evaluate optional flow, and only add to list if it evaluates to TRUE
                requiredList.add(execution);
            } else if (execution.isAlternative()) {
                alternativeList.add(execution);
            }
        }
        //handle required elements : all required elements need to be executed
        boolean requiredElementsSuccessful = true;
        for (AuthenticationExecutionModel required : requiredList) {
            Response response = processSingleFlowExecutionModel(required, null);
            requiredElementsSuccessful &= processor.isSuccessful(required);
            if (response == null) {
                continue;
            }
            return response;
        }

        //Evaluate alternative elements only if there are no required elements
        if (requiredList.isEmpty()) {
            //check if an alternative is already successful, in case we are returning in the flow after an action
            for (AuthenticationExecutionModel alternative : alternativeList) {
                if (processor.isSuccessful(alternative)) {
                    successful = true;
                    return null;
                }
            }

            //handle alternative elements: the first alternative element to be satisfied is enough
            for (AuthenticationExecutionModel alternative : alternativeList) {
                try {
                    Response response = processSingleFlowExecutionModel(alternative, null);
                    if (response == null) {
                        if (processor.isSuccessful(alternative)) {
                            successful = true;
                            return null;
                        }
                        continue;
                    }
                    return response;
                } catch (AuthenticationFlowException afe) {
                    processor.getAuthenticationSession().setExecutionStatus(alternative.getId(), AuthenticationSessionModel.ExecutionStatus.ATTEMPTED);
                    continue;
                }
            }
        } else {
            successful = requiredElementsSuccessful;
        }
        return null;
    }

    private Response processSingleFlowExecutionModel(AuthenticationExecutionModel model, String selectedCredentialId) {
        logger.debugv("check execution: {0} requirement: {1}", model.getAuthenticator(), model.getRequirement().toString());

        if (isProcessed(model)) {
            logger.debug("execution is processed");
            return null;
        }
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
        AuthenticatorFactory factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
        }
        Authenticator authenticator = createAuthenticator(factory);
        logger.debugv("authenticator: {0}", factory.getId());
        UserModel authUser = processor.getAuthenticationSession().getAuthenticatedUser();
        AuthenticationProcessor.Result context = processor.createAuthenticatorContext(model, authenticator, executions);

        createAuthentictorCredentialMap(model, context);
        context.setSelectedCredentialId(selectedCredentialId);

        if (authenticator.requiresUser() && authUser == null) {
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
        Response response = processResult(context, false);
        return response;
    }

    private void createAuthentictorCredentialMap(AuthenticationExecutionModel model, AuthenticationProcessor.Result context) {
        //Add authentication executor - credential list map to context, along with the current credential
        if (model.isAlternative() && processor.getAuthenticationSession() != null && processor.getAuthenticationSession().getAuthenticatedUser() != null) {
            List<AuthenticationExecutionModel> alternativeExecutions = processor.getRealm().getAuthenticationExecutions(model.getParentFlow())
                    .stream().filter(AuthenticationExecutionModel::isAlternative).collect(Collectors.toList());
            MultivaluedMap<AuthenticationExecutionModel, CredentialModel> authCredentialMap = new MultivaluedHashMap<>();
            for (AuthenticationExecutionModel alternativeExecution : alternativeExecutions) {
                Authenticator localAuthenticator = processor.getSession().getProvider(Authenticator.class, alternativeExecution.getAuthenticator());
                if (localAuthenticator instanceof CredentialValidator) {
                    CredentialValidator cv = (CredentialValidator) localAuthenticator;
                    authCredentialMap.addAll(alternativeExecution, cv.getCredentials(processor.getSession(), processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser()));
                } else {
                    authCredentialMap.putSingle(alternativeExecution, null);
                }
            }
            context.setAuthCredentialMap(authCredentialMap);
        }
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
