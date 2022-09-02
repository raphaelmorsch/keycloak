package org.keycloak.crypto.fips.test;

import org.junit.Assume;
import org.junit.Before;
import org.keycloak.common.util.Environment;
import org.keycloak.util.KeyStoreTest;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FIPS1402KeystoreTest extends KeyStoreTest {

    @Before
    public void before() {
        // Run this test just if java is in FIPS mode
        Assume.assumeTrue("Java is not in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }
}
