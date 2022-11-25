package ee.cyber.cdoc20.client;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.client.model.Capsule;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.Resources;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

/**
 * KeyCapsuleClient initialization from properties file.
 */
public final class KeyCapsuleClientImpl implements KeyCapsuleClient, KeyCapsuleClientFactory {
    private static final Logger log = LoggerFactory.getLogger(KeyCapsuleClientImpl.class);

    private final String serverId;
    private final Cdoc20KeyCapsuleApiClient postClient; // TLS client
    private final Cdoc20KeyCapsuleApiClient getClient; // mTLS client
    @Nullable
    private KeyStore clientKeyStore; //initialised only from #create(Properties)

    private KeyCapsuleClientImpl(String serverIdentifier,
                                  Cdoc20KeyCapsuleApiClient postClient,
                                  Cdoc20KeyCapsuleApiClient getClient,
                                  @Nullable KeyStore clientKeyStore) {
        this.serverId = serverIdentifier;
        this.postClient = postClient;
        this.getClient = getClient;
        this.clientKeyStore = clientKeyStore;
    }

    public static KeyCapsuleClient create(String serverIdentifier,
                                           Cdoc20KeyCapsuleApiClient postClient,
                                           Cdoc20KeyCapsuleApiClient getClient) {
        return new KeyCapsuleClientImpl(serverIdentifier, postClient, getClient, null);
    }

    public static KeyCapsuleClient create(Properties p) throws GeneralSecurityException, IOException {
        return create(p, true);
    }

    /**
     * Create KeyCapsulesClient from properties file
     * @param p properties
     * @param initMutualTlsClient if false then mutual TLS (get-server) client is not initialized.
     *            Useful, when client is only used for creating KeyCapsules (encryption). Initializing mTLS client may
     *            require special hardware (smart-card or crypto token) and/or interaction with the user.
     * <p>
     *            If false and {@link KeyCapsuleClient#getCapsule(String)} is called, then IllegalStateException is
     *            thrown.
     * @return KeyCapsulesClient
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static KeyCapsuleClient create(Properties p, boolean initMutualTlsClient)
            throws GeneralSecurityException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("KeyServer properties:");
            p.forEach((key, value) -> log.debug("{}={}", key, value));
        }

        String serverId = p.getProperty("cdoc20.client.server.id");

        Cdoc20KeyCapsuleApiClient.Builder builder = Cdoc20KeyCapsuleApiClient.builder()
                .withTrustKeyStore(loadTrustKeyStore(p));

        getInteger(p, "cdoc20.client.server.connect-timeout")
                .ifPresent(builder::withConnectTimeoutMs);
        getInteger(p, "cdoc20.client.server.read-timeout")
                .ifPresent(builder::withReadTimeoutMs);
        getBoolean(p, "cdoc20.client.server.debug")
                .ifPresent(builder::withDebuggingEnabled);

        String postBaseUrl = p.getProperty("cdoc20.client.server.base-url.post");
        String getBaseUrl = p.getProperty("cdoc20.client.server.base-url.get");

        // postClient can be configured with client key store,
        Cdoc20KeyCapsuleApiClient postClient = builder
                .withBaseUrl(postBaseUrl)
                .build();

        // client key store configuration required
        Cdoc20KeyCapsuleApiClient getClient = null;
        KeyStore clientKeyStore = null;
        if (initMutualTlsClient) {
            clientKeyStore = loadClientKeyStore(p);
            getClient = builder
                    .withClientKeyStore(clientKeyStore)
                    .withClientKeyStoreProtectionParameter(loadClientKeyStoreProtectionParamater(p))
                    .withBaseUrl(getBaseUrl)
                    .build();
        }

        return new KeyCapsuleClientImpl(serverId, postClient, getClient, clientKeyStore);
    }

    public static KeyCapsuleClientFactory createFactory(Properties p) throws GeneralSecurityException, IOException {
        return (KeyCapsuleClientFactory) create(p);
    }

    static KeyStore.ProtectionParameter loadClientKeyStoreProtectionParamater(Properties  p) {
        String prompt = p.getProperty("cdoc20.client.ssl.client-store-password.prompt");
        if (prompt != null) {
            log.debug("Using interactive client KS protection param");
            return ECKeys.getKeyStoreCallbackProtectionParameter(prompt + ":");
        }

        String pw = p.getProperty("cdoc20.client.ssl.client-store-password");
        if (pw != null) {
            log.debug("Using password for client KS");
            return new KeyStore.PasswordProtection(pw.toCharArray());
        }

        return null;
    }

    static Optional<Boolean> getBoolean(Properties p, String name) {
        String value = p.getProperty(name);
        if (value != null) {
            return Optional.of(Boolean.parseBoolean(value));
        }
        return Optional.empty();
    }

    static Optional<Integer> getInteger(Properties p, String name) {
        String value = p.getProperty(name);
        if (value != null) {
            try {
                return Optional.of(Integer.parseInt(value));
            } catch (NumberFormatException nfe) {
                log.warn("Invalid int value {} for property {}. Ignoring.", value, name);
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param p properties to load the key store
     * @throws KeyStoreException if no Provider supports a KeyStoreSpi implementation for the specified type in
     *      properties file
     * @throws IOException – if an I/O error occurs,
     *      if there is an I/O or format problem with the keystore data,
     *      if a password is required but not given,
     *      or if the given password was incorrect. If the error is due to a wrong password,
     *      the cause of the IOException should be an UnrecoverableKeyException
     * @return client key store or null if not defined in properties
     * @KeyStoreException
     * @IOException
     */
    static @Nullable KeyStore loadClientKeyStore(Properties p) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {

        KeyStore clientKeyStore;
        String type = p.getProperty("cdoc20.client.ssl.client-store.type", null);

        if (null == type) {
            return null;
        }

        if ("PKCS12".equalsIgnoreCase(type)) {
            clientKeyStore = KeyStore.getInstance(type);

            String clientStoreFile = p.getProperty("cdoc20.client.ssl.client-store");
            String passwd = p.getProperty("cdoc20.client.ssl.client-store-password");

            clientKeyStore.load(Resources.getResourceAsStream(clientStoreFile),
                    (passwd != null) ? passwd.toCharArray() : null);

        } else if ("PKCS11".equalsIgnoreCase(type)) {
            String openScLibPath = loadOpenScLibPath(p);
            KeyStore.ProtectionParameter protectionParameter = loadClientKeyStoreProtectionParamater(p);

            // default slot 0 - Isikutuvastus
            clientKeyStore = ECKeys.initPKCS11KeysStore(openScLibPath, null, protectionParameter);
        } else {
            throw new IllegalArgumentException("cdoc20.client.ssl.client-store.type " + type + " not supported");
        }

        return clientKeyStore;
    }

    /**
     * If "opensclibrary" property is set in properties or System properties, return value specified. If both specify
     * value then use one from System properties
     * @param p properties provided
     * @return "opensclibrary" value specified in properties or null if not property not present
     */
    static String loadOpenScLibPath(Properties p) {
        // try to load from System Properties (initialized using -D) and from properties file provided.
        // Give priority to System property
        return System.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY,
                p.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY, null));
    }

    /**
     *
     * @param p properties to load the key store
     * @return Keystore loaded based on properties
     * @throws KeyStoreException if no Provider supports a KeyStoreSpi implementation for the specified type in
     *      properties file
     * @throws IOException – if an I/O error occurs,
     *      if there is an I/O or format problem with the keystore data,
     *      if a password is required but not given,
     *      or if the given password was incorrect. If the error is due to a wrong password,
     *      the cause of the IOException should be an UnrecoverableKeyException
     * @IOException
     * @KeyStoreException
     * @CertificateException – if any of the certificates in the keystore could not be loaded
     */
    static KeyStore loadTrustKeyStore(Properties p) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
        KeyStore trustKeyStore;

        String type = p.getProperty("cdoc20.client.ssl.trust-store.type", "JKS");

        String trustStoreFile = p.getProperty("cdoc20.client.ssl.trust-store");
        String passwd = p.getProperty("cdoc20.client.ssl.trust-store-password");

        trustKeyStore = KeyStore.getInstance(type);
        trustKeyStore.load(Resources.getResourceAsStream(trustStoreFile),
                (passwd != null) ? passwd.toCharArray() : null);

        return trustKeyStore;
    }

    @Override
    public String storeCapsule(Capsule capsule)
            throws ExtApiException {
        Objects.requireNonNull(postClient);

        try {
            return postClient.createCapsule(capsule);
        } catch (ee.cyber.cdoc20.client.api.ApiException e) {
            throw new ExtApiException(e.getMessage(), e);
        }
    }

    @Override
    public Optional<Capsule> getCapsule(String id) throws ExtApiException {
        if (getClient == null) {
            throw new IllegalStateException("get-server client not initialized");
        }

        try {
            return getClient.getCapsule(id);

        } catch (ee.cyber.cdoc20.client.api.ApiException apiException) {
            throw new ExtApiException(apiException.getMessage(), apiException);
        }

    }

    @Override
    public String getServerIdentifier() {
        return serverId;
    }

    /**
     * Get first certificate from clientKeyStore if its initialized
     * @return first certificate from clientKeyStore or null if not found
     */
    @Nullable
    public Certificate getClientCertificate() {
        return getClientCertificate(null);
    }

    @Nullable
    public Certificate getClientCertificate(@Nullable String alias) {
        if (clientKeyStore != null) {
            try {
                if (alias != null) {
                    return clientKeyStore.getCertificate(alias);
                } else {
                    return clientKeyStore.getCertificate(clientKeyStore.aliases().nextElement());
                }
            } catch (KeyStoreException e) {
                log.debug("Error listing certificate aliases", e);
                return null;
            }
        }

        log.debug("clientKeyStore == null: only initialized for #create(Properties)");
        return null;
    }

    @Override
    public KeyCapsuleClient getForId(String serverIdentifier) {
        if (getServerIdentifier().equals(serverIdentifier)) {
            return this;
        }
        log.warn("Server configuration for {} requested, but {} provided", serverIdentifier, getServerIdentifier());
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyCapsuleClientImpl that = (KeyCapsuleClientImpl) o;
        return Objects.equals(serverId, that.serverId)
                && Objects.equals(postClient, that.postClient)
                && Objects.equals(getClient, that.getClient)
                && Objects.equals(clientKeyStore, that.clientKeyStore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverId, postClient, getClient, clientKeyStore);
    }
}