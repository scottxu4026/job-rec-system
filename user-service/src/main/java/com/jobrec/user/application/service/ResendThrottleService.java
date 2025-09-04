package com.jobrec.user.application.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ResendThrottleService {
    private final Map<String, Window> buckets = new ConcurrentHashMap<>();

    private static class Window { long start; int count; }

    private static final int LIMIT = 3; // max 3 per window
    private static final int WINDOW_SECONDS = 900; // 15 min

    public synchronized boolean allow(String email) {
        long now = Instant.now().getEpochSecond();
        Window w = buckets.computeIfAbsent(email, k -> { Window x = new Window(); x.start = now; x.count = 0; return x; });
        if (now - w.start >= WINDOW_SECONDS) { w.start = now; w.count = 0; }
        if (++w.count > LIMIT) return false;
        return true;
    }
}


