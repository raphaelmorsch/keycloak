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

package org.keycloak.authentication.x509;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;

import org.junit.ClassRule;
import org.keycloak.rule.CryptoInitRule;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.StreamUtil;

/** This is not tested in keycloak-core. The subclasses should be created in the crypto modules to make sure it is tested with corresponding modules (bouncycastle VS bouncycastle-fips) */
public abstract class CertificatePemIdentityExtractorTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testExtractsCertInPemFormat() throws Exception {
        X509Certificate x509Certificate = SubjectAltNameIdentityExtractorTest.getCertificate();

        // TODO:mposolda
        String name1 = x509Certificate.getSubjectDN().getName();
        String name2 = x509Certificate.getSubjectX500Principal().getName();

        String certificatePem = PemUtils.encodeCertificate(x509Certificate);

        //X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel();
        UserIdentityExtractor extractor = CryptoIntegration.getProvider().getIdentityExtractorProvider().getCertificatePemIdentityExtractor();

        String userIdentity = (String) extractor.extractUserIdentity(new X509Certificate[]{x509Certificate});

        assertEquals(certificatePem, userIdentity);
    }

    @Test
    public void testExtractsCertInSubjectDNFormat() throws Exception {
        X509Certificate x509Certificate = SubjectAltNameIdentityExtractorTest.getCertificate();

        UserIdentityExtractor extractor = CryptoIntegration.getProvider().getIdentityExtractorProvider().getX500NameExtractor("CN", certs -> {
            return certs[0].getSubjectX500Principal();
        });
        // TODO:mposolda should this really need to be retyped to string?
        String userIdentity = (String) extractor.extractUserIdentity(new X509Certificate[]{x509Certificate});
        assertEquals("Test User", userIdentity);
    }

}
