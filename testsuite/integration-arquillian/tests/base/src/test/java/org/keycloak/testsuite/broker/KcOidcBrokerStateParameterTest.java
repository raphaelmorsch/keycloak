/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.broker;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.ws.rs.core.Response;

import org.hamcrest.Matchers;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.EventType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.util.WaitUtils;

import static org.junit.Assert.assertThat;
import static org.keycloak.testsuite.AssertEvents.isUUID;
import static org.keycloak.testsuite.broker.BrokerTestConstants.REALM_CONS_NAME;
import static org.keycloak.testsuite.broker.BrokerTestTools.getConsumerRoot;
import static org.keycloak.testsuite.broker.BrokerTestTools.getProviderRoot;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;
import static org.keycloak.testsuite.pages.AppPage.RequestType.AUTH_RESPONSE;

/**
 * Tests related to OIDC "state" parameter used in the OIDC AuthorizationResponse sent by the IDP to the SP
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KcOidcBrokerStateParameterTest extends AbstractInitializedBaseBrokerTest {

    @Page
    protected AppPage appPage;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration() {

            @Override
            public List<ClientRepresentation> createProviderClients() {
                List<ClientRepresentation> clients = super.createProviderClients();

                List<String> redirectUris = new ArrayList<>();
                redirectUris.add(getConsumerRoot() + "/auth/realms/" + REALM_CONS_NAME + "/*");
                clients.get(0).setRedirectUris(redirectUris);

                return clients;
            }
        };
    }

    @Test
    public void testMissingStateParameter() {
        BrokerConfiguration brokerConfig = getBrokerConfiguration();
        final String LINK = oauth.AUTH_SERVER_ROOT + "/realms/" + brokerConfig.consumerRealmName() + "/broker/" + brokerConfig.getIDPAlias() + "/endpoint?code=foo123";

        driver.navigate().to(LINK);
        waitForPage(driver, "sign in to consumer", true);

        errorPage.assertCurrent();
        assertThat(errorPage.getError(), Matchers.is("Missing state parameter in response from identity provider."));
    }

    @Test
    public void testRepeatStateParameter() throws Exception {
        driver.navigate().to(getAccountUrl(getConsumerRoot(), bc.consumerRealmName()));

        waitForPage(driver, "sign in to", true);
        loginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "sign in to", true);

        // Manually change the URL and refresh the page. This will redirect us to the "app" endpoint once the authentication finish.
        // This will allow to simulate repeated request
        String url = driver.getCurrentUrl();
        String origRedirectUri = UriUtils.decodeQueryString(url).getFirst(OAuth2Constants.REDIRECT_URI);
        String replacedAppRedirectUri = origRedirectUri.replaceAll("/" + bc.consumerRealmName() + "/.*", "/" + bc.consumerRealmName() + "/app/auth");
        String replacedURLOfProviderLoginPage = KeycloakUriBuilder.fromUri(url)
                .replaceQueryParam(OAuth2Constants.REDIRECT_URI, replacedAppRedirectUri)
                .build().toString();
        driver.navigate().to(replacedURLOfProviderLoginPage);
        waitForPage(driver, "sign in to", true);

        // Login. Should be on the "app" page now
        loginPage.login(bc.getUserLogin(), bc.getUserPassword());
        Assert.assertEquals(AUTH_RESPONSE, appPage.getRequestType());

        // Replace URL again. Now make sure that we trigger broker endpoint on the "consumer" side with the code+state parameters
        String currentQueryString = new URL(driver.getCurrentUrl()).getQuery();
        String brokerRedirectUri = KeycloakUriBuilder.fromUri(origRedirectUri)
                .replaceQuery(currentQueryString)
                .build().toString();

        events.clear();

        // Trigger the URL now. Verify that codeToToken error was thrown on provider side and loginEvent was thrown on consumer side
        String providerRealmId = realmsResouce().realm(bc.providerRealmName()).toRepresentation().getId();
        String consumerRealmId = realmsResouce().realm(bc.consumerRealmName()).toRepresentation().getId();
        driver.navigate().to(brokerRedirectUri);

        events.expect(EventType.CODE_TO_TOKEN_ERROR)
                .clearDetails()
                .session(isUUID())
                .realm(providerRealmId)
                .user(isUUID())
                .client("brokerapp")
                .error("invalid_code")
                .assertEvent();

        events.expect(EventType.LOGIN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(consumerRealmId)
                .user((String) null)
                .client((String) null)
                .error("identity_provider_login_failure")
                .assertEvent();

        // Trigger the URL again. Verify that only loginEvent on consumer side. The codeToToken request should *not* be triggered due the already used "state" on consumer endpoint
        // TODO:mposolda The type of the error should be different due the failure at authenticationSession verification
        driver.navigate().to(brokerRedirectUri);

        events.expect(EventType.LOGIN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(consumerRealmId)
                .user((String) null)
                .client((String) null)
                .error("identity_provider_login_failure")
                .assertEvent();
    }


}
