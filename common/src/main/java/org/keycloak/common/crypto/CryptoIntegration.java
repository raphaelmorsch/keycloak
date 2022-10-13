package org.keycloak.common.crypto;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.jboss.logging.Logger;
import org.keycloak.common.util.BouncyIntegration;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CryptoIntegration {

    protected static final Logger logger = Logger.getLogger(CryptoIntegration.class);

    private static final Object lock = new Object();
    private static volatile CryptoProvider cryptoProvider;

    public static void init(ClassLoader classLoader) {
        if (cryptoProvider == null) {
            synchronized (lock) {
                if (cryptoProvider == null) {
                    cryptoProvider = detectProvider(classLoader);
                    logger.debugv("java security provider: {0}", BouncyIntegration.PROVIDER);

                }
            }
        }

        if (logger.isTraceEnabled()) {
            logger.tracef(dumpJavaSecurityProviders());
            logger.tracef(dumpSecurityProperties());
        }
    }

    public static CryptoProvider getProvider() {
        if (cryptoProvider == null) {
            throw new IllegalStateException("Illegal state. Please init first before obtaining provider");
        }
        return cryptoProvider;
    }


    // Try to auto-detect provider
    private static CryptoProvider detectProvider(ClassLoader classLoader) {
        List<CryptoProvider> foundProviders = StreamSupport.stream(ServiceLoader.load(CryptoProvider.class, classLoader).spliterator(), false)
                .collect(Collectors.toList());

        if (foundProviders.isEmpty()) {
            throw new IllegalStateException("Not able to load any cryptoProvider with the classLoader: " + classLoader);
        } else if (foundProviders.size() > 1) {
            throw new IllegalStateException("Multiple crypto providers loaded with the classLoader: " + classLoader +
                    ". Make sure only one cryptoProvider available on the classpath. Available providers: " +foundProviders);
        } else {
            logger.debugf("Detected crypto provider: %s", foundProviders.get(0).getClass().getName());
            return foundProviders.get(0);
        }
    }

    public static String dumpJavaSecurityProviders() {
        StringBuilder builder = new StringBuilder("Java security providers: [ \n");
        for (Provider p : Security.getProviders()) {
            builder.append(" " + p.toString() + " - " + p.getClass() + ", \n");
        }
        return builder.append("]").toString();
    }

    // TODO:mposolda consider removing some of the properties
    public static String dumpSecurityProperties() {
        return String.format("Default keystore type: %s, truststore type system property: %s, keystore type system property: %s, truststore system property: %s, keystore type compat: %s, " +
                        "security properties: %s, truststore provider type: %s",
                KeyStore.getDefaultType(),
                System.getProperty("javax.net.ssl.trustStoreType"),
                System.getProperty("javax.net.ssl.keyStoreType"),
                System.getProperty("javax.net.ssl.trustStore"),
                Security.getProperty("keystore.type.compat"),
                System.getProperty("java.security.properties"),
                System.getProperty("javax.net.ssl.trustStoreProvider")
        );
    }

    public static void setProvider(CryptoProvider provider) {
        logger.debugf("Using the crypto provider: %s", provider.getClass().getName());
        cryptoProvider = provider;
    }
}
