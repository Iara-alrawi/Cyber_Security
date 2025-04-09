package se.gritacademy;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitingFilter implements Filter {
    private static final int RATE_LIMIT = 5; // Max requests per minute
    private static final long WINDOW_SIZE = 60000; // 1 minute in milliseconds

    private final ConcurrentHashMap<String, RequestCounter> ipCounters = new ConcurrentHashMap<>();

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // Applicera rate limitation endast om Authorization-header saknas (d.v.s. ej inloggad)
        if (request.getHeader("Authorization") == null || request.getHeader("Authorization").isEmpty()) {
            String ip = request.getRemoteAddr();
            RequestCounter counter = ipCounters.computeIfAbsent(ip, k -> new RequestCounter());
            long currentTime = System.currentTimeMillis();

            // Om fönstret är slut, nollställ räknaren
            if (currentTime - counter.timestamp >= WINDOW_SIZE) {
                counter.timestamp = currentTime;
                counter.count.set(0);
            }

            if (counter.count.incrementAndGet() > RATE_LIMIT) {
                response.setStatus(429);
                response.getWriter().write("Too Many Requests");
                return;
            }
        }
        chain.doFilter(req, res);
    }

    private static class RequestCounter {
        volatile long timestamp;
        AtomicInteger count = new AtomicInteger(0);

        RequestCounter() {
            this.timestamp = System.currentTimeMillis();
        }
    }
}
