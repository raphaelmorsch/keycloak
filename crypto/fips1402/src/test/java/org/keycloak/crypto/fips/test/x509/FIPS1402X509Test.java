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

package org.keycloak.crypto.fips.test.x509;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.junit.Assume;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.util.Environment;
import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.rule.CryptoInitRule;

import static org.junit.Assert.assertEquals;

/**
 * TODO:mposolda refactor this test or somehow check how to handle it for both default and fips1402
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FIPS1402X509Test {

    protected static final Logger logger = Logger.getLogger(FIPS1402X509Test.class);

    private static final Map<String, String> CUSTOM_OIDS = new HashMap<>();
    private static final Map<String, String> CUSTOM_OIDS_REVERSED = new HashMap<>();
    static {
        CUSTOM_OIDS.put("2.5.4.5", "serialNumber".toUpperCase());
        CUSTOM_OIDS.put("2.5.4.15", "businessCategory".toUpperCase());
        CUSTOM_OIDS.put("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName".toUpperCase());
        CUSTOM_OIDS.put("1.2.840.113549.1.9.1", "emailAddress".toUpperCase());

        // Reverse map
        for (Map.Entry<String, String> entry : CUSTOM_OIDS.entrySet()) {
            CUSTOM_OIDS_REVERSED.put(entry.getValue(), entry.getKey());
        }
        CUSTOM_OIDS_REVERSED.put("E", "1.2.840.113549.1.9.1");
    }

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Before
    public void before() {
        // Run this test just if java is in FIPS mode
        Assume.assumeTrue("Java is not in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }

    @Test
    public void testExtractsCertInPemFormat() throws Exception {
        InputStream is = getClass().getResourceAsStream("/certs/UPN-cert.pem");
        X509Certificate x509Certificate = PemUtils.decodeCertificate(StreamUtil.readString(is, Charset.defaultCharset()));
        logger.infof("X509 certificate subject DN: %s", x509Certificate.getSubjectDN().getName());

        logger.infof("X509 certificate subject DN RFC2253: %s", x509Certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));


        logger.infof("X509 certificate subject DN RFC2253 with map: %s", x509Certificate.getSubjectX500Principal().getName(X500Principal.RFC2253, CUSTOM_OIDS));

        logger.infof("Matches 1: %s", matches("EMAILADDRESS=test@somecompany.com,CN=Test User,OU=Some Department,O=Some Company,ST=District of Columbia,C=US", x509Certificate));
        logger.infof("Matches 2: %s", matches("E=test@somecompany.com,CN=Test User,OU=Some Department,O=Some Company,ST=District of Columbia,C=US" , x509Certificate));




//        String certificatePem = PemUtils.encodeCertificate(x509Certificate);
//
//        //X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel();
//        UserIdentityExtractor extractor = CryptoIntegration.getProvider().getIdentityExtractorProvider().getCertificatePemIdentityExtractor();
//
//        String userIdentity = (String) extractor.extractUserIdentity(new X509Certificate[]{x509Certificate});
//
//        assertEquals(certificatePem, userIdentity);
    }

    private boolean matches(String checkedDN, X509Certificate x509Certificate) {
        X500Principal expectedDNPrincipal = new X500Principal(checkedDN, CUSTOM_OIDS_REVERSED);
        return expectedDNPrincipal.getName(X500Principal.RFC2253, CUSTOM_OIDS).equals(x509Certificate.getSubjectX500Principal().getName(X500Principal.RFC2253, CUSTOM_OIDS));
    }
}
