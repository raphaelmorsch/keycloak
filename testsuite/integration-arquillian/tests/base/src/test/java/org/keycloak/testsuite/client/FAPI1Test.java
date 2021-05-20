/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.client;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.hamcrest.Matchers;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.adapters.authentication.JWTClientSecretCredentialsProvider;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.common.Profile;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.UriUtils;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.condition.AnyClientConditionFactory;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.OAuthGrantPage;
import org.keycloak.testsuite.util.OAuthClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * Test for the FAPI 1 specifications:
 * - Financial-grade API Security Profile 1.0 - Part 1: Baseline - https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server
 * - Financial-grade API Security Profile 1.0 - Part 2: Advanced - https://openid.net/specs/openid-financial-api-part-2-1_0.html
 *
 * Mostly tests the builtin FAPI policies work as expected
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@EnableFeature(value = Profile.Feature.CLIENT_POLICIES, skipRestart = true)
public class FAPI1Test extends AbstractClientPoliciesTest {

    @Page
    protected ErrorPage errorPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected OAuthGrantPage grantPage;

    @Page
    protected AppPage appPage;


    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        List<UserRepresentation> users = realm.getUsers();

        LinkedList<CredentialRepresentation> credentials = new LinkedList<>();
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue("password");
        credentials.add(password);

        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername("john");
        user.setCredentials(credentials);
        user.setClientRoles(Collections.singletonMap(Constants.REALM_MANAGEMENT_CLIENT_ID, Arrays.asList(AdminRoles.CREATE_CLIENT, AdminRoles.MANAGE_CLIENTS)));
        users.add(user);

        realm.setUsers(users);

        testRealms.add(realm);
    }


    @Test
    public void testFAPIBaselineClientAuthenticator() throws Exception {
        setupPolicyFAPIBaselineForAllClient();

        // Try to register client with clientIdAndSecret - should fail
        try {
            createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(ClientIdAndSecretAuthenticator.PROVIDER_ID);
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Try to register client with "client-jwt" - should pass
        String clientUUID = createClientByAdmin("client-jwt", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Try to register client with "client-secret-jwt" - should pass
        clientUUID = createClientByAdmin("client-secret-jwt", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Try to register client with "client-x509" - should pass
        clientUUID = createClientByAdmin("client-x509", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(X509ClientAuthenticator.PROVIDER_ID);
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(X509ClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Try to register client with default authenticator - should pass. Client authenticator should be "client-jwt"
        clientUUID = createClientByAdmin("client-jwt-2", (ClientRepresentation clientRep) -> {
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Check the Consent is enabled, PKCS set to S256
        Assert.assertTrue(client.isConsentRequired());
        Assert.assertEquals(OAuth2Constants.PKCE_METHOD_S256, OIDCAdvancedConfigWrapper.fromClientRepresentation(client).getPkceCodeChallengeMethod());
    }


    @Test
    public void testFAPIBaselineOIDCClientRegistration() throws Exception {
        setupPolicyFAPIBaselineForAllClient();

        // Try to register client with clientIdAndSecret - should fail
        try {
            createClientDynamically(generateSuffixedName("foo"), (OIDCClientRepresentation clientRep) -> {
                clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.CLIENT_SECRET_BASIC);
            });
            fail();
        } catch (ClientRegistrationException e) {
            assertEquals(ERR_MSG_CLIENT_REG_FAIL, e.getMessage());
        }

        // Try to register client with "client-jwt" - should pass
        String clientUUID = createClientDynamically("client-jwt", (OIDCClientRepresentation clientRep) -> {
            clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);
            clientRep.setJwksUri("https://foo");
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Set new initialToken for register new clients
        setInitialAccessTokenForDynamicClientRegistration();

        // Try to register client with "client-secret-jwt" - should pass
        clientUUID = createClientDynamically("client-secret-jwt", (OIDCClientRepresentation clientRep) -> {
            clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.CLIENT_SECRET_JWT);
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Set new initialToken for register new clients
        setInitialAccessTokenForDynamicClientRegistration();

        // Try to register client with "client-x509" - should pass
        clientUUID = createClientDynamically("client-x509", (OIDCClientRepresentation clientRep) -> {
            clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.TLS_CLIENT_AUTH);
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(X509ClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Check the Consent is enabled, PKCS set to S256
        Assert.assertTrue(client.isConsentRequired());
        Assert.assertEquals(OAuth2Constants.PKCE_METHOD_S256, OIDCAdvancedConfigWrapper.fromClientRepresentation(client).getPkceCodeChallengeMethod());

    }


    @Test
    public void testFAPIBaselineRedirectUri() throws Exception {
        setupPolicyFAPIBaselineForAllClient();

        // Try to register redirect_uri like "http://hostname.com" - should fail
        try {
            String clientUUID = createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setRedirectUris(Collections.singletonList("http://hostname.com"));
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Try to register redirect_uri like "https://hostname.com/foo/*" - should fail due the wildcard
        try {
            createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setRedirectUris(Collections.singletonList("https://hostname.com/foo/*"));
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Try to register redirect_uri like "https://hostname.com" - should pass
        String clientUUID = createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
            clientRep.setRedirectUris(Collections.singletonList("https://hostname.com"));
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertNames(client.getRedirectUris(), "https://hostname.com");
    }


    @Test
    public void testFAPIBaselineConfidentialClientLogin() throws Exception {
        setupPolicyFAPIBaselineForAllClient();

        // Register client (default authenticator)
        String clientUUID = createClientByAdmin("foo", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
            clientRep.setSecret("secret");
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertFalse(client.isPublicClient());
        Assert.assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        checkPKCEWithS256RequiredDuringLogin("foo");

        // Setup PKCE
        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);

        checkNonceAndStateForCurrentClientDuringLogin();
        checkRedirectUriForCurrentClientDuringLogin();

        // Check PKCE with S256, redirectUri and nonce/state set. Login should be successful
        successfulLoginAndLogout("foo", false, "secret", codeVerifier);
    }


    @Test
    public void testFAPIBaselinePublicClientLogin() throws Exception {
        setupPolicyFAPIBaselineForAllClient();

        // Register client as public client
        String clientUUID = createClientByAdmin("foo", (ClientRepresentation clientRep) -> {
            clientRep.setPublicClient(true);
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertTrue(client.isPublicClient());

        checkPKCEWithS256RequiredDuringLogin("foo");

        // Setup PKCE
        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);

        checkNonceAndStateForCurrentClientDuringLogin();
        checkRedirectUriForCurrentClientDuringLogin();

        // Check PKCE with S256, redirectUri and nonce/state set. Login should be successful
        successfulLoginAndLogout("foo", true, null, codeVerifier);
    }


    @Test
    public void testFAPIAdvancedClientRegistration() throws Exception {
        // Set "advanced" policy
        setupPolicyFAPIAdvancedForAllClient();

        // Register client with clientIdAndSecret - should fail
        try {
            createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(ClientIdAndSecretAuthenticator.PROVIDER_ID);
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Register client with signedJWT - should fail
        try {
            createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Register client with privateKeyJWT, but unsecured redirectUri - should fail
        try {
            createClientByAdmin("invalid", (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
                clientRep.setRedirectUris(Collections.singletonList("http://foo"));
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getMessage());
        }

        // Try to register client with "client-jwt" - should pass
        String clientUUID = createClientByAdmin("client-jwt", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
        });
        ClientRepresentation client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Try to register client with "client-x509" - should pass
        clientUUID = createClientByAdmin("client-x509", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(X509ClientAuthenticator.PROVIDER_ID);
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(X509ClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Try to register client with default authenticator - should pass. Client authenticator should be "client-jwt"
        clientUUID = createClientByAdmin("client-jwt-2", (ClientRepresentation clientRep) -> {
        });
        client = getClientByAdmin(clientUUID);
        Assert.assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());

        // Check the Consent is enabled, Holder-of-key is enabled and default signature algorithm
        Assert.assertTrue(client.isConsentRequired());
        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        Assert.assertTrue(clientConfig.isUseMtlsHokToken());
        Assert.assertEquals(Algorithm.PS256, clientConfig.getIdTokenSignedResponseAlg());
        Assert.assertEquals(Algorithm.PS256, clientConfig.getRequestObjectSignatureAlg().toString());
    }


    @Test
    public void testFAPIAdvancedPublicClientLoginNotPossible() throws Exception {
        // TODO:mposolda implement what I lost yesterday... Baseline policy, then followed by public client login
    }

    @Test
    public void testFAPIAdvancedSignatureAlgorithms() throws Exception {
        // TODO:mposolda
        // Test that unsecured algorithm is not possible

        // Test that secured algorithm is possible to explicitly set

        // Test default algorithms set everywhere
    }


    @Test
    public void testFAPIAdvancedLoginWithPrivateKeyJWT() throws Exception {
        // TODO:mposolda
        // Register client with private-key-jwt

        // Check login - response type

        // Check login request object (maybe request object signed by different algorithm, expired request object)

        // Check HoK required

        // Login with private-key-jwt client authentication etc
    }

    @Test
    public void testFAPIAdvancedLoginWithMTLS() throws Exception {
        // TODO:mposolda Same like "testFAPIAdvancedLoginWithPrivateKeyJWT" but just different client authenticator

    }





    private void checkPKCEWithS256RequiredDuringLogin(String clientId) {
        // Check PKCE required - login without PKCE should fail
        oauth.clientId(clientId);
        oauth.openLoginForm();
        assertRedirectedToClientWithError(OAuthErrorException.INVALID_REQUEST,"Missing parameter: code_challenge_method");

        // Check PKCE required - login with "plain" PKCE should fail
        oauth.codeChallenge("234567890_234567890123");
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_PLAIN);
        oauth.openLoginForm();
        assertRedirectedToClientWithError(OAuthErrorException.INVALID_REQUEST,"Invalid parameter: code challenge method is not configured one");
    }

    // Assumption is that clientId is already set in "oauth" client when this method is called. Also assumption is that PKCE parameters are properly set (in case PKCE required for the client)
    private void checkNonceAndStateForCurrentClientDuringLogin() {
        oauth.openLoginForm();
        assertRedirectedToClientWithError(OAuthErrorException.INVALID_REQUEST,"Missing parameter: nonce");

        // Check "state" required in non-OIDC request
        oauth.nonce("123456");
        oauth.stateParamHardcoded(null);
        oauth.openid(false);
        oauth.openLoginForm();
        assertRedirectedToClientWithError(OAuthErrorException.INVALID_REQUEST,"Missing parameter: state");

        // Revert to default "state" parameter generator
        oauth.stateParamRandom();
    }

    private void checkRedirectUriForCurrentClientDuringLogin() {
        String origRedirectUri = oauth.getRedirectUri();

        // Check redirect_uri required
        oauth.openid(true);
        oauth.redirectUri(null);
        oauth.openLoginForm();
        errorPage.assertCurrent();
        Assert.assertEquals("Invalid parameter: redirect_uri", errorPage.getError());

        // Revert redirectUri
        oauth.redirectUri(origRedirectUri);
    }


    private void setupPolicyFAPIBaselineForAllClient() throws Exception {
        String json = (new ClientPoliciesBuilder()).addPolicy(
                (new ClientPolicyBuilder()).createPolicy("MyPolicy", "Policy for enable FAPI Baseline for all clients", Boolean.TRUE)
                        .addCondition(AnyClientConditionFactory.PROVIDER_ID,
                                createAnyClientConditionConfig())
                        .addProfile(FAPI1_BASELINE_PROFILE_NAME)
                        .toRepresentation()
        ).toString();
        updatePolicies(json);
    }

    private void setupPolicyFAPIAdvancedForAllClient() throws Exception {
        String json = (new ClientPoliciesBuilder()).addPolicy(
                (new ClientPolicyBuilder()).createPolicy("MyPolicy", "Policy for enable FAPI Advanced for all clients", Boolean.TRUE)
                        .addCondition(AnyClientConditionFactory.PROVIDER_ID,
                                createAnyClientConditionConfig())
                        .addProfile(FAPI1_ADVANCED_PROFILE_NAME)
                        .toRepresentation()
        ).toString();
        updatePolicies(json);
    }

    // TODO:mposolda Need to have this method to handle also "client-jwt" authentication? Maybe have supplier of client authentication provided here?
    private void successfulLoginAndLogout(String clientId, boolean publicClient, String clientSecret, String codeVerifier) throws Exception {
        oauth.clientId(clientId);
        oauth.doLogin("john", "password");

        grantPage.assertCurrent();
        grantPage.assertGrants(OAuthGrantPage.PROFILE_CONSENT_TEXT, OAuthGrantPage.EMAIL_CONSENT_TEXT, OAuthGrantPage.ROLES_CONSENT_TEXT);
        grantPage.accept();
        Assert.assertTrue(oauth.getCurrentQuery().containsKey(OAuth2Constants.CODE));

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        OAuthClient.AccessTokenResponse tokenResponse;
        if (publicClient) {
            oauth.codeVerifier(codeVerifier);
            tokenResponse = oauth.doAccessTokenRequest(code, null);
        } else {
            String signedJwt = getClientSecretSignedJWT(clientSecret, Algorithm.HS256);
            tokenResponse = doAccessTokenRequestWithClientSignedJWT(code, signedJwt, codeVerifier);
        }

        assertEquals(200, tokenResponse.getStatusCode());
        Assert.assertThat(tokenResponse.getIdToken(), Matchers.notNullValue());
        Assert.assertThat(tokenResponse.getAccessToken(), Matchers.notNullValue());

        // Scope parameter must be present per FAPI
        Assert.assertNotNull(tokenResponse.getScope());
        assertScopes("openid profile email", tokenResponse.getScope());

        // Logout and remove consent of the user for next logins
        oauth.doLogout(tokenResponse.getRefreshToken(), clientSecret);
        revokeConsent(clientId);
    }


    private String getClientSecretSignedJWT(String secret, String algorithm) {
        JWTClientSecretCredentialsProvider jwtProvider = new JWTClientSecretCredentialsProvider();
        jwtProvider.setClientSecret(secret, algorithm);
        return jwtProvider.createSignedRequestToken(oauth.getClientId(), getRealmInfoUrl(), algorithm);
    }

    private String getRealmInfoUrl() {
        String authServerBaseUrl = UriUtils.getOrigin(oauth.getRedirectUri()) + "/auth";
        return KeycloakUriBuilder.fromUri(authServerBaseUrl).path(ServiceUrlConstants.REALM_INFO_PATH).build("test").toString();
    }

    private OAuthClient.AccessTokenResponse doAccessTokenRequestWithClientSignedJWT(String code, String signedJwt, String codeVerifier) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CODE_VERIFIER, codeVerifier));
        parameters.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, oauth.getRedirectUri()));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        CloseableHttpResponse response = sendRequest(oauth.getAccessTokenUrl(), parameters);
        return new OAuthClient.AccessTokenResponse(response);
    }

    private CloseableHttpResponse sendRequest(String requestUrl, List<NameValuePair> parameters) throws Exception {
        CloseableHttpClient client = new DefaultHttpClient();
        try {
            HttpPost post = new HttpPost(requestUrl);
            UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
            post.setEntity(formEntity);
            return client.execute(post);
        } finally {
            oauth.closeClient(client);
        }
    }

    public static void assertScopes(String expectedScope, String receivedScope) {
        Collection<String> expectedScopes = Arrays.asList(expectedScope.split(" "));
        Collection<String> receivedScopes = Arrays.asList(receivedScope.split(" "));
        Assert.assertTrue("Not matched. expectedScope: " + expectedScope + ", receivedScope: " + receivedScope,
                expectedScopes.containsAll(receivedScopes) && receivedScopes.containsAll(expectedScopes));
    }


    private void assertRedirectedToClientWithError(String expectedError, String expectedErrorDescription) {
        appPage.assertCurrent();
        assertEquals(expectedError, oauth.getCurrentQuery().get(OAuth2Constants.ERROR));
        assertEquals(expectedErrorDescription, oauth.getCurrentQuery().get(OAuth2Constants.ERROR_DESCRIPTION));
    }

    private void revokeConsent(String clientId) {
        UserResource user = ApiUtil.findUserByUsernameId(adminClient.realm(REALM_NAME), "john");
        List<Map<String, Object>> consents = user.getConsents();
        org.junit.Assert.assertEquals(1, consents.size());
        user.revokeConsent(clientId);
    }
}
