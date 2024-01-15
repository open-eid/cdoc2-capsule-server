package ee.cyber.cdoc20.crypto;

import java.security.Key;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial extends Destroyable {

    /**
     * @return the key to derive the encryption key
     */
    Key getKey();

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * @return the encryption key type
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * @return salt used to derive the key from the password
     */
    default byte[] getPasswordSalt() {
        return new byte[0];
    }

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param publicKey public key
     * @param keyLabel  key label
     * @param keyOrigin encryption key origin
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPublicKey(
        PublicKey publicKey, String keyLabel, EncryptionKeyOrigin keyOrigin
    ) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return publicKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public EncryptionKeyOrigin getKeyOrigin() {
                return keyOrigin;
            }

            @Override
            public void destroy() {
                // no secret key material that needs to be destroyed
            }
        };
    }

    /**
     * Create EncryptionKeyMaterial from secret.
     * To decrypt CDOC, recipient must also have same preSharedKey that is identified by the same
     * keyLabel
     * @param preSharedKey preSharedKey will be used to generate key encryption key
     * @param keyLabel     unique identifier for preSharedKey
     * @param keyOrigin    encryption key origin
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromSecret(
        SecretKey preSharedKey, String keyLabel, EncryptionKeyOrigin keyOrigin
    ) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return preSharedKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public EncryptionKeyOrigin getKeyOrigin() {
                return keyOrigin;
            }

            @Override
            public void destroy() throws DestroyFailedException {
                preSharedKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return preSharedKey.isDestroyed();
            }
        };
    }

    /**
     * Create EncryptionKeyMaterial from password.
     * To decrypt CDOC, recipient must also have same preSharedKey and salt that are identified by
     * the same keyLabel
     * @param preSharedKey preSharedKey will be used to generate key encryption key
     * @param keyLabel     unique identifier for preSharedKey
     * @param keyOrigin    encryption key origin
     * @param salt         the salt used to derive the key from the password
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPassword(
        SecretKey preSharedKey, String keyLabel, EncryptionKeyOrigin keyOrigin, byte[] salt
    ) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return preSharedKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public EncryptionKeyOrigin getKeyOrigin() {
                return keyOrigin;
            }

            @Override
            public byte[] getPasswordSalt() {
                return salt;
            }

            @Override
            public void destroy() throws DestroyFailedException {
                preSharedKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return preSharedKey.isDestroyed();
            }
        };
    }
}
