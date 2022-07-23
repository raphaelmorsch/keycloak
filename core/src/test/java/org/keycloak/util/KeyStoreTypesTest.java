package org.keycloak.util;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.jboss.logging.Logger;
import org.junit.Test;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class KeyStoreTypesTest {

    protected final Logger logger = Logger.getLogger(getClass());

    protected void testKeyStoreProvider(String format) throws Exception {
        logger.infof("Testing keystore format: %s", format);
        String subject = "example-subject";
        String keyAlias = subject;
        String keyPassword = "password";

        KeyPair keyPair = KeyUtils.generateRsaKeyPair(2048);
        X509Certificate certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, subject);

        String privateKeyPem = PemUtils.encodeKey(keyPair.getPrivate());
        String certPem = PemUtils.encodeCertificate(certificate);

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(format);
        } catch (KeyStoreException kse) {
            logger.warnf("Failed to load keystore format '%s'. Will fallback to BC provider", format);
            keyStore = KeyStore.getInstance(format, BouncyIntegration.PROVIDER);
        }
        keyStore.load(null, null);

        Certificate[] chain =  {certificate};
        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPassword.trim().toCharArray(), chain);
    }
}
