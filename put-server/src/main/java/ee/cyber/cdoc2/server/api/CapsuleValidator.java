package ee.cyber.cdoc2.server.api;

import ee.cyber.cdoc2.shared.crypto.ECKeys;
import ee.cyber.cdoc2.shared.crypto.EllipticCurve;
import ee.cyber.cdoc2.shared.crypto.RsaUtils;
import java.io.IOException;


import lombok.extern.slf4j.Slf4j;


import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

import ee.cyber.cdoc2.server.generated.model.Capsule;

import static ee.cyber.cdoc2.shared.crypto.EllipticCurve.*;

/**
 * Utility class for validating capsules.
 */
@Slf4j
public final class CapsuleValidator {

    private CapsuleValidator() {
        // utility class
    }

    static boolean isValid(Capsule capsule) {
        return switch (capsule.getCapsuleType()) {
            case ECC_SECP256R1, ECC_SECP384R1, ECC_SECP521R1 -> validateEcCapsule(capsule);
            case RSA -> validateRSACapsule(capsule);
            default ->
                throw new IllegalArgumentException("Unexpected capsule type: " + capsule.getCapsuleType());
        };
    }

    private static boolean validateEcCapsule(Capsule capsule) {

        try {
            EllipticCurve curve = switch (capsule.getCapsuleType()) {
                case ECC_SECP256R1 -> SECP256R1;
                case ECC_SECP384R1 -> SECP384R1;
                case ECC_SECP521R1 -> SECP521R1;
                default -> throw new IllegalArgumentException("Must be a elliptic curve capsule");
            };

            int tlsEncodedKeyLen = 2 * curve.getKeyLength() + 1;

            if (capsule.getRecipientId() == null || capsule.getEphemeralKeyMaterial() == null) {
                log.error("Recipient id or ephemeral key was null");
                return false;
            }
            if (capsule.getRecipientId().length != tlsEncodedKeyLen
                    || capsule.getEphemeralKeyMaterial().length != tlsEncodedKeyLen) {
                log.error("Invalid {} curve key length", capsule.getCapsuleType());
                return false;
            }

            ECPublicKey recipientPubKey = ECKeys.decodeEcPublicKeyFromTls(curve, capsule.getRecipientId());
            ECPublicKey senderPubKey = ECKeys.decodeEcPublicKeyFromTls(curve, capsule.getEphemeralKeyMaterial());

            return (ECKeys.isValidPublicKey(curve, recipientPubKey) && ECKeys.isValidPublicKey(curve, senderPubKey));
        } catch (GeneralSecurityException gse) {
            log.error("Invalid {} EC key", capsule.getCapsuleType(), gse);
        }
        return false;
    }

    private static boolean validateRSACapsule(Capsule capsule) {

        try {
            RsaUtils.decodeRsaPubKey(capsule.getRecipientId());
            return true;
        } catch (GeneralSecurityException | IOException exc) {
            log.error("Failed to parse capsule recipient's RSA public key", exc);
            return false;
        }
    }
}
