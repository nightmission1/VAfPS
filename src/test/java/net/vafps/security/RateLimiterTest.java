package net.vafps.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RateLimiterTest {

    @Test
    @DisplayName("Untrusted IP gets quarantined after reaching failure threshold")
    void testUntrustedIpQuarantine() throws Exception {
        NetworkShield shield = new NetworkShield(true, List.of("127.0.0.1/32"));
        RateLimiter limiter = new RateLimiter(shield, 3, 10_000L, 500L);

        InetAddress untrusted = InetAddress.getByName("192.168.1.50");

        assertEquals(RateLimiter.QuarantineAction.ALLOWED, limiter.checkIp(untrusted));

        limiter.recordAuthFailure(untrusted);
        limiter.recordAuthFailure(untrusted);
        assertEquals(RateLimiter.QuarantineAction.ALLOWED, limiter.checkIp(untrusted));

        limiter.recordAuthFailure(untrusted);
        // 3. hatadan sonra karantina
        assertEquals(RateLimiter.QuarantineAction.QUARANTINED, limiter.checkIp(untrusted));
    }

    @Test
    @DisplayName("Trusted IP gets tarpitted instead of blocked")
    void testTrustedIpTarpit() throws Exception {
        NetworkShield shield = new NetworkShield(true, List.of("127.0.0.0/8"));
        RateLimiter limiter = new RateLimiter(shield, 3, 10_000L, 500L);

        InetAddress trusted = InetAddress.getByName("127.0.0.1");

        limiter.recordAuthFailure(trusted);
        limiter.recordAuthFailure(trusted);
        limiter.recordAuthFailure(trusted);

        assertEquals(RateLimiter.QuarantineAction.TARPIT, limiter.checkIp(trusted));

        // Başarılı girişte sıfırlanmalı
        limiter.recordAuthSuccess(trusted);
        assertEquals(RateLimiter.QuarantineAction.ALLOWED, limiter.checkIp(trusted));
    }
}
