package ee.cyber.cdoc2.server;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import ee.cyber.cdoc2.server.config.DbConnectionConfigProperties;


/**
 * Cleanup job for expired CDOC2 key capsule table
 */
@Component
@Slf4j
@RequiredArgsConstructor
public final class ExpiredCapsuleCleanUpJob {

    private Connection dbConnection;
    private final DbConnectionConfigProperties configProperties;

    @PostConstruct
    void init() {
        dbConnection = createDbConnection();
    }

    /**
     * Executes the stored procedure {@code expired_cdoc2_capsule_cleanup()} in CDOC2 database
     */
    @Scheduled(cron = "${key-capsule.expired.clean-up.cron}")
    public void cleanUpExpiredCapsules() {
        log.debug("Executing expired key capsules deletion from database");

        String query = "CALL expired_cdoc2_capsule_cleanup()";
        try (CallableStatement stmt = dbConnection.prepareCall(query)) {
            stmt.execute();
            int updateCount = stmt.getUpdateCount();
            if (updateCount == -1L) {
                throw new SQLException("Database update operation has failed");
            }
            log.info("Total number of successfully deleted expired key capsules is {}", updateCount);
        } catch (SQLException e) {
            String errorMsg = "Expired key capsules deletion has failed";
            log.error(errorMsg);
            throw new RuntimeException(errorMsg, e);
        }
    }

    private Connection createDbConnection() {
        try {
            return DriverManager.getConnection(
                configProperties.url(),
                configProperties.username(),
                configProperties.password()
            );
        } catch (SQLException e) {
            String errorMsg = "Failed to establish database connection";
            log.error(errorMsg);
            throw new RuntimeException(errorMsg, e);
        }
    }

    @PreDestroy
    public void preDestroy() throws SQLException {
        dbConnection.close();
    }

}
