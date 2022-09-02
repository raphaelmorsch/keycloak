package org.keycloak.util;

import java.security.KeyStore;

import org.jboss.logging.Logger;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.rule.CryptoInitRule;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class KeyStoreTest {

    protected final Logger logger = Logger.getLogger(getClass());

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testKeystore() throws Exception {
        logger.infof("Default keystore type: %s", KeyStore.getDefaultType());

        logKeyStore("JKS");
        logKeyStore("PKCS12");
        logKeyStore("PKCS11");
        logKeyStore("BCFKS");

        logKeyStoreBC("JKS");
        logKeyStoreBC("PKCS12");
        logKeyStoreBC("PKCS11");
        logKeyStoreBC("BCFKS");
    }

    private void logKeyStore(String type) {
        try {
            KeyStore keystore = KeyStore.getInstance(type);
            logger.infof("Keystore.getInstance('%s')= keystore of provider '%s'. Details: %s", type, keystore.getProvider().getName(), keystore);
        } catch (Exception e) {
            logger.errorf(e, "Not found keystore for type %s", type);
        }
    }

    private void logKeyStoreBC(String type) {
        try {
            KeyStore keystore = KeyStore.getInstance(type, BouncyIntegration.PROVIDER);
            logger.infof("Keystore.getInstance('%s', '%s') = %s", type, BouncyIntegration.PROVIDER, keystore);
        } catch (Exception e) {
            logger.errorf(e, "Not found keystore for type %s in the bouncycastle provider %s", type, BouncyIntegration.PROVIDER);
        }
    }
}
