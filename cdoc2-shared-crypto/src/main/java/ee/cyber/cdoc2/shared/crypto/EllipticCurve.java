package ee.cyber.cdoc2.shared.crypto;

import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Elliptic curve enums mapped to known elliptic curve names and oid's
 */
public enum EllipticCurve {

    UNKNOWN(null, null, 0),
    // https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html
    // Table 4-28 Recommended Curves Provided by the SunEC Provider
    SECP384R1("secp384r1", "1.3.132.0.34", 384 / 8),
    SECP256R1("secp256r1", "1.2.840.10045.3.1.7", 256 / 8);

    private static final Logger log = LoggerFactory.getLogger(EllipticCurve.class);

    private final String name;
    private final String oid;
    private final int keyLengthBytes;

    EllipticCurve(String name, String oid, int keyLengthBytes) {
        this.name = name;
        this.oid = oid;
        this.keyLengthBytes = keyLengthBytes;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }

    /**
     * Key length in bytes. For secp384r1, its 384/8=48
     */
    public int getKeyLength() {
        if (this == UNKNOWN) {
            throw new IllegalStateException("getKeyLength not implemented for " + this);
        }
        return keyLengthBytes;
    }

    public static EllipticCurve forOid(String oid) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.oid.equals(oid)) {
                return curve;
            }
        }
        throw new NoSuchAlgorithmException("Unknown EC curve oid " + oid);
    }

    public static EllipticCurve forName(String name) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.name.equals(name)) {
                return curve;
            }
        }
        throw new NoSuchAlgorithmException("Unknown EC curve name " + name);
    }

}