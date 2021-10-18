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

package org.keycloak;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.DerUtils;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CertificateTest {

    // Custom OIDs defined in the OpenBanking Brasil - https://openbanking-brasil.github.io/specs-seguranca/open-banking-brasil-certificate-standards-1_ID1.html#name-client-certificate
    // These are not recognized by default in RFC1779 or RFC2253 and hence not read in the java by default
    private static final Map<String, String> CUSTOM_OIDS = new HashMap<>();
    static {
        CUSTOM_OIDS.put("2.5.4.5", "serialNumber".toUpperCase());
        CUSTOM_OIDS.put("2.5.4.15", "businessCategory".toUpperCase());
        CUSTOM_OIDS.put("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName".toUpperCase());
    }

    private static final Map<String, String> CUSTOM_OIDS2 = new HashMap<>();
    static {
        CUSTOM_OIDS2.put("serialNumber".toUpperCase(), "2.5.4.5");
        CUSTOM_OIDS2.put("businessCategory".toUpperCase(), "2.5.4.15");
        CUSTOM_OIDS2.put("jurisdictionCountryName".toUpperCase(), "1.3.6.1.4.1.311.60.2.1.3");
    }

    @Test
    public void testCertificate() throws Exception {
        BouncyIntegration.init();
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("obb-certificate.pem");
        X509Certificate cert = DerUtils.decodeCertificate(is);
        System.out.println("cert.getSubjectDN().getName(): " + cert.getSubjectDN().getName());

        System.out.println("X500Principal.RFC2253: " + cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
        System.out.println("X500Principal.RFC2253(CUSTOM_OIDS): " + cert.getSubjectX500Principal().getName(X500Principal.RFC2253, CUSTOM_OIDS));
        System.out.println("X500Principal.RFC1779: " + cert.getSubjectX500Principal().getName(X500Principal.RFC1779));
        System.out.println("CANONICAL: " + cert.getSubjectX500Principal().getName(X500Principal.CANONICAL));

        X500Principal myPrincipal1 = new X500Principal("UID=299833f9-e2ac-4251-a8d2-ddedd608da03,1.3.6.1.4.1.311.60.2.1.3=#13024252,2.5.4.15=#130f427573696e65737320456e74697479,2.5.4.5=#130e3037323337333733303030313230,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR");
        X500Principal myPrincipal2 = new X500Principal("UID=c88e02ad-a6c5-4974-94b8-5775d99bcfbd,1.3.6.1.4.1.311.60.2.1.3=#13024252,2.5.4.15=#130f427573696e65737320456e74697479,2.5.4.5=#130e3037323337333733303030313230,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR", CUSTOM_OIDS2);
        X500Principal myPrincipal3 = new X500Principal("UID=c88e02ad-a6c5-4974-94b8-5775d99bcfbd,JURISDICTIONCOUNTRYNAME=BR,BUSINESSCATEGORY=Business Entity,SERIALNUMBER=07237373000120,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR", CUSTOM_OIDS2);


//        System.out.println("Comparison1: " + myPrincipal1.equals(cert.getSubjectX500Principal()));
//        System.out.println("Comparison2: " + myPrincipal2.equals(cert.getSubjectX500Principal()));
//        System.out.println("Comparison3: " + myPrincipal3.equals(cert.getSubjectX500Principal()));

        // RFC2253 - unresolved entities (This is used by OpenBanking Certification testsuite)
        System.out.println("Comparison1: " + compareCertificates("UID=c88e02ad-a6c5-4974-94b8-5775d99bcfbd,1.3.6.1.4.1.311.60.2.1.3=#13024252,2.5.4.15=#130f427573696e65737320456e74697479,2.5.4.5=#130e3037323337333733303030313230,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR", cert));

        // RFC2253 - resolved entities
        System.out.println("Comparison2: " + compareCertificates("UID=c88e02ad-a6c5-4974-94b8-5775d99bcfbd,JURISDICTIONCOUNTRYNAME=BR,BUSINESSCATEGORY=Business Entity,SERIALNUMBER=07237373000120,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR", cert));

        // RFC2253 - different UID (Comparison should fail)
        System.out.println("Comparison3: " + compareCertificates("UID=299833f9-e2ac-4251-a8d2-ddedd608da03,1.3.6.1.4.1.311.60.2.1.3=#13024252,2.5.4.15=#130f427573696e65737320456e74697479,2.5.4.5=#130e3037323337333733303030313230,CN=openbanking.bnb.gov.br,OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,O=BCO DO NORDESTE DO BRASIL S.A.,L=Fortaleza,ST=CE,C=BR", cert));

        // Canonical format
        System.out.println("Comparison4: " + compareCertificates("uid=c88e02ad-a6c5-4974-94b8-5775d99bcfbd,1.3.6.1.4.1.311.60.2.1.3=#13024252,2.5.4.15=#130f427573696e65737320456e74697479,2.5.4.5=#130e3037323337333733303030313230,cn=openbanking.bnb.gov.br,ou=a60b7fb5-f7f3-5536-a41f-1bff137f47d1,o=bco do nordeste do brasil s.a.,l=fortaleza,st=ce,c=br", cert));

        // RFC1779 - expected true
        System.out.println("Comparison5: " + compareCertificates("OID.0.9.2342.19200300.100.1.1=c88e02ad-a6c5-4974-94b8-5775d99bcfbd, OID.1.3.6.1.4.1.311.60.2.1.3=BR, OID.2.5.4.15=Business Entity, OID.2.5.4.5=07237373000120, CN=openbanking.bnb.gov.br, OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1, O=BCO DO NORDESTE DO BRASIL S.A., L=Fortaleza, ST=CE, C=BR", cert));

        // RFC1779 - expected false
        System.out.println("Comparison6: " + compareCertificates("OID.0.9.2342.19200300.100.1.1=c88e02ad-a6c5-4974-94b8-5775d99bcfbd, OID.1.3.6.1.4.1.311.60.2.1.3=BR, OID.2.5.4.15=Business Entty, OID.2.5.4.5=07237373000120, CN=openbanking.bnb.gov.br, OU=a60b7fb5-f7f3-5536-a41f-1bff137f47d1, O=BCO DO NORDESTE DO BRASIL S.A., L=Fortaleza, ST=CE, C=BR", cert));


        System.out.println("foo");
    }

    private boolean compareCertificates(String expectedDN, X509Certificate cert) {
        X500Principal expectedDNPrincipal = new X500Principal(expectedDN, CUSTOM_OIDS2);
        return expectedDNPrincipal.equals(cert.getSubjectX500Principal());
    }
}
