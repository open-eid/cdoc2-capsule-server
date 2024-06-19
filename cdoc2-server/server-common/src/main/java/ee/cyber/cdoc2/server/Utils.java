package ee.cyber.cdoc2.server;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.ZoneOffset;


/**
 * Server utilities.
 */
public final class Utils {

    private Utils() {
    }

    public static URI getPathAndQueryPart(URI fullURI) throws URISyntaxException {
        // return only path and query part of URI as host and port might be different, when running behind load balancer

        String uriStr = fullURI.toString();
        URI uri = new URI(uriStr).normalize();

        if (uri.getQuery() != null) {
            return new URI(uri.getPath() + '?' + uri.getQuery());
        } else {
            return new URI(uri.getPath());
        }
    }

    public static OffsetDateTime toOffsetDateTime(LocalDateTime expiryTime) {
        return OffsetDateTime.of(expiryTime, ZoneOffset.UTC);
    }

    public static long getDurationTotalMonths(String duration) {
        Period expiryPeriod = Period.parse(duration);
        return expiryPeriod.toTotalMonths();
    }

}
