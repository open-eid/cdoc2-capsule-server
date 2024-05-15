package ee.cyber.cdoc2.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;


/**
 * Security configuration properties
 */
@ConfigurationProperties(prefix = "management.endpoints.metrics")
public record ConfigProperties(String username, String password) {
}
