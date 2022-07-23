package org.keycloak.crypto.fips.test;

import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.rule.CryptoInitRule;
import org.keycloak.util.KeyStoreTypesTest;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FIPS1402KeystoreTypesTest extends KeyStoreTypesTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testJKSFormat() throws Exception {
        testKeyStoreProvider("JKS");
    }

    @Test
    public void testPKCS12Format() throws Exception {
        testKeyStoreProvider("PKCS12");
    }

    @Test
    public void testPKCS11Format() throws Exception {
        testKeyStoreProvider("PKCS11");
    }

    @Test
    public void testBCFIPSFormat() throws Exception {
        testKeyStoreProvider("BCFKS");
    }
}
