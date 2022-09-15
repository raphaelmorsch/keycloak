package org.keycloak.crypto.fips.test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.rule.CryptoInitRule;

/**
 * TODO:mposolda probably remove
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class Pbkdf2TempTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    protected static final Logger logger = Logger.getLogger(Pbkdf2TempTest.class);

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static final int DEFAULT_ITERATIONS = 27500;

    public static final int DERIVED_KEY_SIZE = 512;


    @Test
    public void test1() {
        logger.infof("BC FIPS approved mode: %b, FIPS Status: %s", CryptoServicesRegistrar.isInApprovedOnlyMode(), FipsStatus.getStatusMessage());
        testPassword("admin");
    }

    private void testPassword(String password) {
        PasswordCredentialModel passwordCred = encodedCredential(password);
        logger.infof("Password secret data: %s, password credential data: %s", passwordCred.getSecretData(), passwordCred.getCredentialData());

        CryptoServicesRegistrar.setApprovedOnlyMode(true);
        logger.infof("BC FIPS approved mode: %b, FIPS Status: %s", CryptoServicesRegistrar.isInApprovedOnlyMode(), FipsStatus.getStatusMessage());

        String paddedPassword = FipsApprovedMode.pbkdfPad(password);
        logger.infof("Password to check after padding: %s", paddedPassword);
        boolean verif = verify(paddedPassword, passwordCred);
        Assert.assertTrue(verif);
    }

    public PasswordCredentialModel encodedCredential(String rawPassword) {
        int iterations = DEFAULT_ITERATIONS;

        byte[] salt = getSalt();
        String encodedPassword = encodedCredential(rawPassword, iterations, salt, DERIVED_KEY_SIZE);

        return PasswordCredentialModel.createFromValues(PBKDF2_ALGORITHM, salt, iterations, encodedPassword);
    }


    public String encode(String rawPassword) {
        int iterations = DEFAULT_ITERATIONS;

        byte[] salt = getSalt();
        return encodedCredential(rawPassword, iterations, salt, DERIVED_KEY_SIZE);
    }


    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        String encodedPassword1 = encodedCredential(rawPassword, credential.getPasswordCredentialData().getHashIterations(), credential.getPasswordSecretData().getSalt(), keySize(credential));
        logger.infof("Encoded password 1: %s", encodedPassword1);

        String encodedPassword2 = encodedCredential("admin", credential.getPasswordCredentialData().getHashIterations(), credential.getPasswordSecretData().getSalt(), keySize(credential));
        logger.infof("Encoded password 2: %s", encodedPassword2);

        return encodedPassword1.equals(credential.getPasswordSecretData().getValue());
    }

    private int keySize(PasswordCredentialModel credential) {
        try {
            byte[] bytes = Base64.decode(credential.getPasswordSecretData().getValue());
            return bytes.length * 8;
        } catch (IOException e) {
            throw new RuntimeException("Credential could not be decoded", e);
        }
    }

    public void close() {
    }

    private String encodedCredential(String rawPassword, int iterations, byte[] salt, int derivedKeySize) {
        KeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, iterations, derivedKeySize);

        try {
            byte[] key = getSecretKeyFactory().generateSecret(spec).getEncoded();
            return Base64.encodeBytes(key);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Credential could not be encoded", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    private SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance(PBKDF2_ALGORITHM, BouncyIntegration.PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("PBKDF2 algorithm not found", e);
        }
    }

    static class FipsApprovedMode {
        // private static final String FIPS_MODE_INDICATOR = "org.bouncycastle.fips.approved_only";
        private static final int MIN_PBKDF_PASSWORD_LENGTH = 14;

        public static String pbkdfPad(String raw) {
            // In fips mode, the pbkdf function does not allow less than 14 characters.
            // During login, the user provided value needs to be hashed, and the password hashing fails
            // because of this functionality of the pbkdf fucntion.
            // As a workaround, we pad smaller inputs with nulls to ensure that a raw value is always at least
            // 14 characters.
            if ( CryptoServicesRegistrar.isInApprovedOnlyMode() && raw.length() < MIN_PBKDF_PASSWORD_LENGTH) {
                int nPad = MIN_PBKDF_PASSWORD_LENGTH - raw.length();
                String result = raw;
                for (int i = 0 ; i < nPad; i++) result += "\0";
                return result;
            }else
                return raw;
        }
    }
}
