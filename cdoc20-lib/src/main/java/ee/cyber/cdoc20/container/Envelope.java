package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.crypto.ChaChaCipher;
import ee.cyber.cdoc20.crypto.Crypto;


import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.header.PayloadEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKey;
import lombok.EqualsAndHashCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;

import static ee.cyber.cdoc20.fbs.header.Details.*;

@EqualsAndHashCode
public class Envelope {
    private static final Logger log = LoggerFactory.getLogger(Envelope.class);


    public static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 2;

    public static final int MIN_HEADER_LEN = 1; //TODO: find out min header len


    private static final byte payloadEncByte = PayloadEncryptionMethod.CHACHA20POLY1305;

    //private final byte[] fmkKeyBuf;
    private final Details.EccRecipient[] eccRecipients;

    private final SecretKey hmacKey;

    //content encryption  key
    private final SecretKey cekKey;


    private Envelope(Details.EccRecipient[] recipients, SecretKey hmacKey, SecretKey cekKey) {
        //this.fmkKeyBuf = fmkKey;
        this.eccRecipients = recipients;
        this.hmacKey = hmacKey;
        this.cekKey = cekKey;
    }

    private Envelope(Details.EccRecipient[] recipients, byte[] fmk) {
        this.eccRecipients = recipients;
        this.hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        this.cekKey = Crypto.deriveContentEncryptionKey(fmk);
    }

    public static Envelope prepare(byte[] fmk, KeyPair senderEcKeyPair, List<ECPublicKey> recipients) throws NoSuchAlgorithmException, InvalidKeyException {

        log.trace("Envelope::build");
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        List<Details.EccRecipient> eccRecipientList = new LinkedList<>();

        for (ECPublicKey otherPubKey: recipients) {
            byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, otherPubKey, Crypto.CEK_LEN_BYTES);
            //log.debug("          kek: {}", HexFormat.of().formatHex(kek));//FIXME: remove
            byte[] encryptedFmk = Crypto.xor(fmk, kek);
            Details.EccRecipient eccRecipient = new Details.EccRecipient(otherPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk);
            //log.debug("          fmk: {}", HexFormat.of().formatHex(fmk));//FIXME: remove
            log.debug("encrypted FMK: {}", HexFormat.of().formatHex(encryptedFmk));
            eccRecipientList.add(eccRecipient);
        }

        SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        return new Envelope(eccRecipientList.toArray(new Details.EccRecipient[0]), hmacKey, cekKey);
    }

//    static Envelope fromInputStream(InputStream envelopeIs, KeyPair recipientEcKeyPair) throws GeneralSecurityException, IOException, CDocParseException {
//
//        log.trace("Envelope::fromInputStream");
//        ECPublicKey recipientPubKey = (ECPublicKey) recipientEcKeyPair.getPublic();
//        ByteArrayOutputStream fileHeaderOs = new ByteArrayOutputStream();
//
//        List<Details.EccRecipient> details = parseHeader(envelopeIs, fileHeaderOs);
//
//        for( Details.EccRecipient detailsEccRecipient : details) {
//            ECPublicKey senderPubKey = detailsEccRecipient.getSenderPubKey();
//            if (recipientPubKey.equals(detailsEccRecipient.getRecipientPubKey())) {
//                byte[] kek = Crypto.deriveKeyDecryptionKey(recipientEcKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
//                byte[] fmk = Crypto.xor(kek, detailsEccRecipient.getEncryptedFileMasterKey());
//
//                Envelope envelope = new Envelope(new Details.EccRecipient[] {detailsEccRecipient}, fmk);
//
//                if (envelopeIs.available() > Crypto.HHK_LEN_BYTES) {
//                    byte[] calculatedHmac = Crypto.calcHmacSha256(envelope.hmacKey, fileHeaderOs.toByteArray());
//                    byte[] hmac = envelopeIs.readNBytes(Crypto.HHK_LEN_BYTES);
//
//                    if (!Arrays.equals(calculatedHmac, hmac)) {
//                        log.debug("calc hmac: {}", HexFormat.of().formatHex(calculatedHmac));
//                        log.debug("file hmac: {}", HexFormat.of().formatHex(hmac));
//
//                        throw new CDocParseException("Invalid hmac");
//                    }
//                } else {
//                    throw new CDocParseException("No hmac");
//                }
//
//                return envelope;
//            }
//        }
//
//        log.info("No matching EC pub key found");
//        throw new CDocParseException("No matching EC pub key found");
//    }

    public static CipherInputStream decrypt(InputStream envelopeIs, KeyPair recipientEcKeyPair) throws GeneralSecurityException, IOException, CDocParseException {
        log.trace("Envelope::fromInputStream");
        ECPublicKey recipientPubKey = (ECPublicKey) recipientEcKeyPair.getPublic();
        ByteArrayOutputStream fileHeaderOs = new ByteArrayOutputStream();

        List<Details.EccRecipient> details = parseHeader(envelopeIs, fileHeaderOs);

        for( Details.EccRecipient detailsEccRecipient : details) {
            ECPublicKey senderPubKey = detailsEccRecipient.getSenderPubKey();
            if (recipientPubKey.equals(detailsEccRecipient.getRecipientPubKey())) {
                byte[] kek = Crypto.deriveKeyDecryptionKey(recipientEcKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
                byte[] fmk = Crypto.xor(kek, detailsEccRecipient.getEncryptedFileMasterKey());

                Envelope envelope = new Envelope(new Details.EccRecipient[] {detailsEccRecipient}, fmk);

                if (envelopeIs.available() > Crypto.HHK_LEN_BYTES) {
                    byte[] calculatedHmac = Crypto.calcHmacSha256(envelope.hmacKey, fileHeaderOs.toByteArray());
                    byte[] hmac = envelopeIs.readNBytes(Crypto.HHK_LEN_BYTES);

                    if (!Arrays.equals(calculatedHmac, hmac)) {
                        log.debug("calc hmac: {}", HexFormat.of().formatHex(calculatedHmac));
                        log.debug("file hmac: {}", HexFormat.of().formatHex(hmac));

                        throw new CDocParseException("Invalid hmac");
                    }

                    byte[] additionalData = ChaChaCipher.getAdditionalData(fileHeaderOs.toByteArray(), hmac);
                    return ChaChaCipher.initChaChaInputStream(envelopeIs, envelope.cekKey, additionalData);
                } else {
                    throw new CDocParseException("No hmac");
                }

            }
        }

        log.info("No matching EC pub key found");
        throw new CDocParseException("No matching EC pub key found");
    }




    static List<Details.EccRecipient> parseHeader(InputStream envelopeIs, ByteArrayOutputStream outHeaderOs) throws IOException, CDocParseException, GeneralSecurityException {
        final int envelope_min_len = PRELUDE.length
                + 1 //version 0x02
                + 4 //header length field
                + MIN_HEADER_LEN
                + Crypto.HHK_LEN_BYTES
                + 0 // TODO: payload min size
        ;

        if (envelopeIs.available() < envelope_min_len) {
            throw new CDocParseException("not enough bytes to read, expected min of " + envelope_min_len);
        }

        if (!Arrays.equals(PRELUDE, envelopeIs.readNBytes(PRELUDE.length))) {
            throw new CDocParseException("stream is not CDOC");
        }

        byte version = (byte) envelopeIs.read();
        if (VERSION != version) {
            throw new CDocParseException("Unsupported CDOC version " + version);
        }

        ByteBuffer headerLenBuf = ByteBuffer.allocate(4);
        headerLenBuf.order(ByteOrder.BIG_ENDIAN);
        //noinspection ResultOfMethodCallIgnored
        envelopeIs.read(headerLenBuf.array());
        int headerLen = headerLenBuf.getInt();

        if ((envelopeIs.available() < headerLen + Crypto.HHK_LEN_BYTES)
            || (headerLen < MIN_HEADER_LEN))  {
            throw new CDocParseException("invalid CDOC header length: "+headerLen);
        }

        byte[] headerBytes = envelopeIs.readNBytes(headerLen);

        if (outHeaderOs != null) {
            outHeaderOs.writeBytes(headerBytes);
        }
        Header header = deserializeHeader(headerBytes);

        List<Details.EccRecipient> eccRecipientList = new LinkedList<>();

        for (int i=0; i < header.recipientsLength(); i++) {
            RecipientRecord r = header.recipients(i);

            if( FMKEncryptionMethod.XOR != r.fmkEncryptionMethod() ) {
                throw new CDocParseException("invalid FMK encryption method: "+r.fmkEncryptionMethod());
            }

            if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
                throw new CDocParseException("invalid FMK len: "+ r.encryptedFmkLength());
            }

            ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
            byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
                    encryptedFmkBuf.position(), encryptedFmkBuf.limit());

            log.debug("Parsed encrypted FMK: {}", HexFormat.of().formatHex(encryptedFmkBytes));

            if ( r.detailsType() == recipients_ECCPublicKey) {
                ECCPublicKey detailsEccPublicKey = (ECCPublicKey) r.details(new ECCPublicKey());
                if (detailsEccPublicKey == null) {
                    throw new CDocParseException("error parsing Details");
                }

                try {
                    ECPublicKey recipientPubKey = ECKeys.decodeEcPublicKeyFromTls(detailsEccPublicKey.recipientPublicKeyAsByteBuffer());
                    ECPublicKey senderPubKey = ECKeys.decodeEcPublicKeyFromTls(detailsEccPublicKey.senderPublicKeyAsByteBuffer());

                    eccRecipientList.add(new Details.EccRecipient(r.fmkEncryptionMethod(),
                            recipientPubKey, senderPubKey, encryptedFmkBytes));
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
                }
            } else if (r.detailsType() == recipients_KeyServer){
                log.warn("Details.recipients_KeyServer not implemented");
//            } else if (r.detailsType() == NONE){
//                log.warn("Details.NONE not implemented");
            }
            else {
                log.error("Unknown Details type {}", r.detailsType());
                throw new CDocParseException("Unknown Details type "+r.detailsType());
            }
        }

        return eccRecipientList;
    }

    static Header deserializeHeader(byte[] buf) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
        return  Header.getRootAsHeader(byteBuffer);
    }

    public void encrypt(InputStream payloadIs, OutputStream os) throws IOException {
        log.trace("encrypt");
        os.write(PRELUDE);
        os.write(new byte[]{VERSION});

        byte[] headerBytes = serializeHeader();

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt(headerBytes.length);
        byte[] headerLenBytes = bb.array();

        os.write(headerLenBytes);
        os.write(headerBytes);

        try {
            byte[] hmac = Crypto.calcHmacSha256(hmacKey, headerBytes);
            os.write(hmac);
            byte[] nonce = ChaChaCipher.generateNonce();
            byte[] additionalData = ChaChaCipher.getAdditionalData(headerBytes, hmac);
//            log.debug("nonce: {}", HexFormat.of().formatHex(nonce));
//            log.debug("AAD:   {}", HexFormat.of().formatHex(additionalData));
            try (CipherOutputStream cipherOs = ChaChaCipher.initChaChaOutputStream(os, cekKey, nonce, additionalData)) {
                cipherOs.write(payloadIs.readAllBytes()); //TODO: tar, zip, loop before encryption
                cipherOs.flush();
            }


        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            log.error("error serializing payload", e);
            throw new IOException("error serializing payload", e);
        }
    }

    byte[] serializeHeader() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serializeHeader(baos);
        return baos.toByteArray();
    }

    void serializeHeader(OutputStream os) throws IOException {
        FlatBufferBuilder builder = new FlatBufferBuilder(1024);


        int[] recipients = new int[eccRecipients.length];

        for (int i = 0; i < eccRecipients.length; i++) {
            Details.EccRecipient eccRecipient = eccRecipients[i];

            int recipientPubKeyOffset = builder.createByteVector(eccRecipient.getRecipientPubKeyTlsEncoded()); // TLS 1.3 format
            int senderPubKeyOffset = builder.createByteVector(eccRecipient.getSenderPubKeyTlsEncoded()); // TLS 1.3 format
            int eccPubKeyOffset = ECCPublicKey.createECCPublicKey(builder,
                    eccRecipient.ellipticCurve,
                    recipientPubKeyOffset,
                    senderPubKeyOffset
            );

            int encFmkOffset =
                    RecipientRecord.createEncryptedFmkVector(builder, eccRecipient.getEncryptedFileMasterKey());

            RecipientRecord.startRecipientRecord(builder);
            RecipientRecord.addDetailsType(builder, ee.cyber.cdoc20.fbs.header.Details.recipients_ECCPublicKey);
            RecipientRecord.addDetails(builder, eccPubKeyOffset);

            RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
            RecipientRecord.addFmkEncryptionMethod(builder, FMKEncryptionMethod.XOR);

            int recipientOffset = RecipientRecord.endRecipientRecord(builder);

            recipients[i] = recipientOffset;
        }

        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
        Header.addPayloadEncryptionMethod(builder, payloadEncByte);
        int headerOffset = Header.endHeader(builder);
        Header.finishHeaderBuffer(builder, headerOffset);

        ByteBuffer buf = builder.dataBuffer();
        int bufLen = buf.limit() - buf.position();
        os.write(buf.array(), buf.position(), bufLen);
    }






}
