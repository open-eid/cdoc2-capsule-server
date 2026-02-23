package ee.cyber.cdoc2.shared.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;


/**
 * Elliptic curve enums mapped to known elliptic curve names, OIDs, key lengths,
 * and their BouncyCastle curve instances for point validation.
 */
public enum EllipticCurve {

    UNKNOWN(null, null, 0, null),
    SECP384R1("secp384r1", "1.3.132.0.34",       384 / 8, new SecP384R1Curve()),
    SECP256R1("secp256r1", "1.2.840.10045.3.1.7", 256 / 8, new SecP256R1Curve());

    private final String name;
    private final String oid;
    private final int keyLengthBytes;
    private final ECCurve bcCurve;

    EllipticCurve(String name, String oid, int keyLengthBytes, ECCurve bcCurve) {
        this.name = name;
        this.oid = oid;
        this.keyLengthBytes = keyLengthBytes;
        this.bcCurve = bcCurve;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }

    /**
     * Key length in bytes (e.g. 48 for secp384r1, 32 for secp256r1).
     */
    public int getKeyLength() {
        if (this == UNKNOWN) {
            throw new IllegalStateException("getKeyLength() not supported for UNKNOWN curve");
        }
        return keyLengthBytes;
    }

    /**
     * BouncyCastle ECCurve instance used for point-on-curve validation.
     */
    public ECCurve getBcCurve() {
        if (this == UNKNOWN) {
            throw new IllegalStateException("getBcCurve() not supported for UNKNOWN curve");
        }
        return bcCurve;
    }

    public static EllipticCurve forOid(String oid) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.oid.equals(oid)) {
                return curve;
            }
        }

        throw new NoSuchAlgorithmException("Unknown EC curve OID: " + oid);
    }

    public static EllipticCurve forName(String name) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.name.equals(name.toLowerCase(Locale.ROOT))) {
                return curve;
            }
        }
        throw new NoSuchAlgorithmException("Unknown EC curve name: " + name);
    }

}