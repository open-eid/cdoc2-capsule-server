package ee.cyber.cdoc2.server;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.server.api.CreateKeyCapsuleApi;
import ee.cyber.cdoc2.server.model.Capsule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class CreateKeyCapsuleApiTest extends KeyCapsuleIntegrationTest {

    @Autowired
    private CreateKeyCapsuleApi api;

    @Test
    void shouldCreateCapsuleWithDefaultExpiryTime() throws Exception {
        var rsaCapsule = getRsaCapsule();

        ResponseEntity<Void> response = api.createCapsule(rsaCapsule, null);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    @Test
    void shouldFailToCreateEcCapsuleWithOverloadedExpiryTime() throws Exception {
        var capsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1);

        // Recipient public key TLS encoded and base64 encoded from client-certificate.pem
        File[] certs = {TestData.getKeysDirectory().resolve("ca_certs/client-certificate.pem").toFile()};
        ECPublicKey recipientKey = ECKeys.loadCertKeys(certs).get(0);
        EllipticCurve curve = EllipticCurve.forPubKey(recipientKey);
        capsule.recipientId(ECKeys.encodeEcPubKeyForTls(curve, recipientKey));

        // Sender public key
        KeyPair senderKeyPair = curve.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        capsule.ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        LocalDateTime expiryTime = LocalDateTime.now().plusYears(10);

        assertThrows(
            IllegalArgumentException.class, () ->
                api.createCapsule(capsule, expiryTime)
        );
    }

    @Test
    void shouldFailToCreateRsaCapsuleWithOverloadedExpiryTime() throws Exception {
        var rsaCapsule = getRsaCapsule();

        LocalDateTime expiryTime = LocalDateTime.now().plusYears(10);

        assertThrows(
            IllegalArgumentException.class, () ->
                api.createCapsule(rsaCapsule, expiryTime)
        );
    }

    private Capsule getRsaCapsule() throws Exception {
        var recipientCert = PemTools.loadCertificate(
            new ByteArrayInputStream(
                Files.readAllBytes(TestData.getKeysDirectory().resolve("rsa/client-rsa-2048-cert.pem")
                    .toAbsolutePath())
            )
        );

        return new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.RSA)
            .ephemeralKeyMaterial(UUID.randomUUID().toString().getBytes())
            .recipientId(RsaUtils.encodeRsaPubKey((RSAPublicKey) recipientCert.getPublicKey()));
    }

}
