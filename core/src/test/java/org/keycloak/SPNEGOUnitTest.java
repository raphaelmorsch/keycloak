/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.jboss.logging.Logger;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.common.util.KerberosJdkProvider;
import org.keycloak.rule.CryptoInitRule;

/**
 * TODO:mposolda doublecheck if to remove this class or not. Lots of hardcoded stuff...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class SPNEGOUnitTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testManager() throws Exception {
        Subject serverSubject = new KerberosServerSubjectAuthenticator("/home/mposolda/IdeaProjects/keycloak/testsuite/integration-arquillian/tests/base/target/test-classes/kerberos/http.keytab",
                "HTTP/localhost@KEYCLOAK.ORG").authenticateServerSubject();

        Subject.doAs(serverSubject, new AcceptSecContext());
    }

    private static class AcceptSecContext implements PrivilegedExceptionAction<Boolean> {

        @Override
        public Boolean run() throws Exception {
            GSSContext gssContext = null;
            try {
                GSSManager manager = GSSManager.getInstance();

                Oid[] supportedMechs = new Oid[] { KerberosConstants.KRB5_OID, KerberosConstants.SPNEGO_OID };
                GSSCredential gssCredential = manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, supportedMechs, GSSCredential.ACCEPT_ONLY);
                gssContext = manager.createContext(gssCredential);
                return true;

//                gssContext = establishContext();
//                logAuthDetails(gssContext);
//
//                if (gssContext.isEstablished()) {
//                    if (gssContext.getSrcName() == null) {
//                        log.warn("GSS Context accepted, but no context initiator recognized. Check your kerberos configuration and reverse DNS lookup configuration");
//                        return false;
//                    }
//
//                    authenticatedKerberosPrincipal = gssContext.getSrcName().toString();
//
//                    if (gssContext.getCredDelegState()) {
//                        delegationCredential = gssContext.getDelegCred();
//                    }
//
//                    return true;
//                } else {
//                    return false;
//                }
            } finally {
                if (gssContext != null) {
                    gssContext.dispose();
                }
            }
        }

    }

    public static class KerberosServerSubjectAuthenticator {

        private static final Logger logger = Logger.getLogger(KerberosServerSubjectAuthenticator.class);

        private static final CallbackHandler NO_CALLBACK_HANDLER = new CallbackHandler() {

            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                throw new UnsupportedCallbackException(callbacks[0]);
            }
        };


        private final String keyTab;

        private final String serverPrincipal;
        private LoginContext loginContext;


        public KerberosServerSubjectAuthenticator(String keyTab, String serverPrincipal) {
            this.keyTab = keyTab;
            this.serverPrincipal = serverPrincipal;
        }


        public Subject authenticateServerSubject() throws LoginException {
            Configuration config = createJaasConfiguration();
            loginContext = new LoginContext("does-not-matter", null, NO_CALLBACK_HANDLER, config);
            loginContext.login();
            return loginContext.getSubject();
        }


        public void logoutServerSubject() {
            if (loginContext != null) {
                try {
                    loginContext.logout();
                } catch (LoginException le) {
                    logger.error("Failed to logout kerberos server subject: " + serverPrincipal, le);
                }
            }
        }


        protected Configuration createJaasConfiguration() {
            return KerberosJdkProvider.getProvider().createJaasConfigurationForServer(keyTab, serverPrincipal, true);
        }

    }
}
