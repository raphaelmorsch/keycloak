package org.keycloak.crypto.fips.test;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;

import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Environment;
import org.keycloak.rule.CryptoInitRule;

import static org.hamcrest.Matchers.greaterThan;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FIPS1402SslTest {

    protected static final Logger logger = Logger.getLogger(FIPS1402SslTest.class);

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();


    @BeforeClass
    public static void dumpSecurityProviders() throws Exception {
        // TODO:mposolda remove this lines and insert providers differently at the initialization of CryptoProvider
        Security.insertProviderAt(new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider("fips:BCFIPS"), 3);
        Class<?> clazz = Class.forName("com.sun.net.ssl.internal.ssl.Provider");
        Constructor<?> constr = clazz.getConstructor(String.class);
        Provider sunJSSEProvider = (Provider) constr.newInstance("BCFIPS");
        Security.insertProviderAt(sunJSSEProvider, 4);

        logger.info(CryptoIntegration.dumpJavaSecurityProviders());
    }

    @Before
    public void before() {
        // Run this test just if java is in FIPS mode
        Assume.assumeTrue("Java is not in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }

    @Test
    public void testPkcs12KeyStoreWithPKIXKeyMgrFactory() throws Exception {
        String type = "PKCS12";
        String password = "passwordpassword";

        KeyStore keystore = loadKeystore(type, password);
        String keyMgrDefaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory keyMgrFact = getKeyMgrFactory(password, keystore, keyMgrDefaultAlgorithm);
        testSSLContext(keyMgrFact);
    }

    // This works with BCFIPS, but requires addition of security provider "com.sun.net.ssl.internal.ssl.Provider BCFIPS" to Java Security providers
    @Test
    public void testPkcs12KeyStoreWithSunX509KeyMgrFactory() throws Exception {
        String type = "PKCS12";
        String password = "passwordpassword";

        KeyStore keystore = loadKeystore(type, password);
        String keyMgrDefaultAlgorithm = "SunX509";
        KeyManagerFactory keyMgrFact = getKeyMgrFactory(password, keystore, keyMgrDefaultAlgorithm);
        testSSLContext(keyMgrFact);
    }

    private KeyStore loadKeystore(String type, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance(type);
        InputStream in = FIPS1402SslTest.class.getClassLoader().getResourceAsStream("bcfips-keystore.pkcs12");
        keystore.load(in, password != null ? password.toCharArray() : null);
        logger.infof("Keystore loaded successfully. Type: %s, provider: %s", keystore.getProvider().getName());
        return keystore;
    }

    private KeyManagerFactory getKeyMgrFactory(String password, KeyStore keystore, String keyMgrAlgorithm) throws Exception {
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance(keyMgrAlgorithm);
        char[] keyPassword = password.toCharArray();
        keyMgrFact.init(keystore, keyPassword);
        logger.infof("KeyManagerFactory loaded for algorithm: %s", keyMgrAlgorithm);
        return keyMgrFact;
    }


    private void testSSLContext(KeyManagerFactory keyMgrFact) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyMgrFact.getKeyManagers(), null, null);
        SSLEngine engine = context.createSSLEngine();

        List<String> enabledCipherSuites = Arrays.asList(engine.getEnabledCipherSuites());
        List<String> supportedProtocols = Arrays.asList(context.getDefaultSSLParameters().getProtocols());
        List<String> supportedCiphers = Arrays.asList(engine.getSupportedCipherSuites());

        logger.infof("Enabled ciphersuites: %s", enabledCipherSuites.size());
        logger.infof("Supported protocols: %s", supportedProtocols);
        logger.infof("Supported ciphers size: %d", supportedCiphers.size());
        Assert.assertThat(enabledCipherSuites.size(), greaterThan(0));
        Assert.assertThat(supportedProtocols.size(), greaterThan(0));
        Assert.assertThat(supportedCiphers.size(), greaterThan(0));

        SSLSessionContext sslServerCtx = context.getServerSessionContext();
        Assert.assertNotNull(sslServerCtx);
    }
}
