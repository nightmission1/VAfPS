package net.vafps.security;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Two-tier Rate Limiter providing token-bucket rate limiting and
 * IP brute-force protection with tarpit delays for trusted IPs
 * and quarantine for untrusted IPs.
 */
public class RateLimiter {

    public enum QuarantineAction {
        ALLOWED,
        TARPIT,
        QUARANTINED
    }

    private static class IpAttemptTracker {
        private final AtomicInteger failures = new AtomicInteger(0);
        private volatile long quarantinedUntil = 0;

        public int recordFailure() {
            return failures.incrementAndGet();
        }

        public void reset() {
            failures.set(0);
            quarantinedUntil = 0;
        }

        public boolean isQuarantined() {
            return System.currentTimeMillis() < quarantinedUntil;
        }

        public void quarantineFor(long millis) {
            quarantinedUntil = System.currentTimeMillis() + millis;
        }

        public int getFailures() {
            return failures.get();
        }
    }

    private final ConcurrentHashMap<String, IpAttemptTracker> ipTrackers = new ConcurrentHashMap<>();
    private final NetworkShield networkShield;
    private final int maxFailures;
    private final long quarantineDurationMs;
    private final long tarpitDelayMs;

    public RateLimiter(NetworkShield networkShield) {
        this(networkShield, 5, 60_000L, 2000L); // 5 deneme, 60sn karantina, 2sn tarpit
    }

    public RateLimiter(NetworkShield networkShield, int maxFailures, long quarantineDurationMs, long tarpitDelayMs) {
        this.networkShield = networkShield;
        this.maxFailures = maxFailures;
        this.quarantineDurationMs = quarantineDurationMs;
        this.tarpitDelayMs = tarpitDelayMs;
    }

    /**
     * Checks whether an IP is currently allowed, tarpitted, or quarantined.
     */
    public QuarantineAction checkIp(InetAddress address) {
        String ipKey = NetworkShield.normalize(address).getHostAddress();
        IpAttemptTracker tracker = ipTrackers.get(ipKey);
        if (tracker == null) {
            return QuarantineAction.ALLOWED;
        }

        if (tracker.isQuarantined()) {
            return QuarantineAction.QUARANTINED;
        }

        if (tracker.getFailures() >= maxFailures) {
            boolean trusted = networkShield.isAllowed(address);
            if (trusted) {
                return QuarantineAction.TARPIT;
            } else {
                tracker.quarantineFor(quarantineDurationMs);
                return QuarantineAction.QUARANTINED;
            }
        }

        return QuarantineAction.ALLOWED;
    }

    /**
     * Records a failed login attempt.
     */
    public void recordAuthFailure(InetAddress address) {
        String ipKey = NetworkShield.normalize(address).getHostAddress();
        IpAttemptTracker tracker = ipTrackers.computeIfAbsent(ipKey, k -> new IpAttemptTracker());
        int count = tracker.recordFailure();

        boolean trusted = networkShield.isAllowed(address);
        if (!trusted && count >= maxFailures) {
            tracker.quarantineFor(quarantineDurationMs);
        }
    }

    /**
     * Resets failure counter upon successful login.
     */
    public void recordAuthSuccess(InetAddress address) {
        String ipKey = NetworkShield.normalize(address).getHostAddress();
        IpAttemptTracker tracker = ipTrackers.get(ipKey);
        if (tracker != null) {
            tracker.reset();
        }
    }

    public long getTarpitDelayMs() {
        return tarpitDelayMs;
    }
}
