package ee.cyber.cdoc2.server.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Logging for requests
 */
@Component
@Slf4j
public class RequestLoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        if (request instanceof HttpServletRequest httpRequest) {
            logRequestHeaders(httpRequest);
        }

        chain.doFilter(request, response);
    }

    private void logRequestHeaders(HttpServletRequest request) {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String contentType = request.getHeader("Content-Type");
        String origin = request.getHeader("Origin");

        // Collect all Sec-Fetch-* headers
        var secFetchHeaders = Collections.list(request.getHeaderNames())
            .stream()
            .filter(name -> name.toLowerCase().startsWith("sec-fetch-"))
            .collect(Collectors.toMap(
                name -> name,
                request::getHeader
            ));

        // Build log message
        StringBuilder logMessage = new StringBuilder();
        logMessage.append(String.format("Request: %s %s", method, uri));

        if (contentType != null) {
            logMessage.append(String.format(" | Content-Type: %s", contentType));
        }

        if (origin != null) {
            logMessage.append(String.format(" | Origin: %s", origin));
        }

        if (!secFetchHeaders.isEmpty()) {
            String secFetchInfo = secFetchHeaders.entrySet().stream()
                .map(entry -> String.format("%s: %s", entry.getKey(), entry.getValue()))
                .collect(Collectors.joining(", "));
            logMessage.append(String.format(" | Sec-Fetch headers: [%s]", secFetchInfo));
        }

        log.info(logMessage.toString());
    }
}
