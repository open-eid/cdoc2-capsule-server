package ee.cyber.cdoc2.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;


/**
 * Configuration properties for key capsule. {@code Period#parse} format is implemented for
 * extracting duration dates.
 *
 * @param defaultExpirationDuration default value for capsule expiration period
 * @param maxExpirationDuration max allowed value for capsule expiration period
 */
@ConfigurationProperties(prefix = "key-capsule")
public record KeyCapsuleConfigProperties(
    String defaultExpirationDuration,
    String maxExpirationDuration
) {
}
