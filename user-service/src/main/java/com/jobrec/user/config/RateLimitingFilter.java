package com.jobrec.user.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final class Counter {
        final AtomicInteger count = new AtomicInteger(0);
        volatile long windowStartEpochSeconds;
    }

    private final Map<String, Counter> buckets = new ConcurrentHashMap<>();

    // Limits per endpoint (requests per windowSeconds per IP)
    private static final int REGISTER_LIMIT = 10;
    private static final int LOGIN_LIMIT = 30;
    private static final int RESEND_LIMIT = 5;
    private static final int LINK_LIMIT = 20;
    private static final int WINDOW_SECONDS = 300; // 5 minutes

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.startsWith("/auth/register")
                || path.startsWith("/auth/login")
                || path.startsWith("/auth/resend-verification")
                || path.startsWith("/auth/link-oauth"));
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String ip = request.getRemoteAddr();
        int limit = switchLimit(path);

        String key = path + "|" + ip;
        long nowSec = Instant.now().getEpochSecond();

        Counter counter = buckets.computeIfAbsent(key, k -> {
            Counter c = new Counter();
            c.windowStartEpochSeconds = nowSec;
            return c;
        });

        synchronized (counter) {
            if (nowSec - counter.windowStartEpochSeconds >= WINDOW_SECONDS) {
                counter.windowStartEpochSeconds = nowSec;
                counter.count.set(0);
            }
            if (counter.count.incrementAndGet() > limit) {
                log.warn("Rate limit exceeded for {} from {}", path, ip);
                response.setStatus(429);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write("{\"error\":\"rate_limited\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private int switchLimit(String path) {
        if (path.startsWith("/auth/register")) return REGISTER_LIMIT;
        if (path.startsWith("/auth/login")) return LOGIN_LIMIT;
        if (path.startsWith("/auth/resend-verification")) return RESEND_LIMIT;
        if (path.startsWith("/auth/link-oauth")) return LINK_LIMIT;
        return 60;
    }
}


