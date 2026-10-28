package net.vafps.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkShieldTest {

    private NetworkShield shield;

    @BeforeEach
    void setUp() {
        List<String> defaultCidrs = List.of(
                "127.0.0.0/8",
                "::1/128",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "10.0.0.0/8",
                "fc00::/7",
                "fe80::/10"
        );
        shield = new NetworkShield(true, defaultCidrs);
    }

    @Test
    @DisplayName("Loopback IPv4 and IPv6 addresses must be allowed")
    void testLoopbackAllowed() throws UnknownHostException {
        assertTrue(shield.isAllowed(InetAddress.getByName("127.0.0.1")));
        assertTrue(shield.isAllowed(InetAddress.getByName("127.0.0.42")));
        assertTrue(shield.isAllowed(InetAddress.getByName("::1")));
    }

    @Test
    @DisplayName("IPv4-mapped IPv6 loopback should be normalized and allowed")
    void testIpv4MappedLoopback() throws UnknownHostException {
        assertTrue(shield.isAllowed(InetAddress.getByName("::ffff:127.0.0.1")));
    }

    @Test
    @DisplayName("Local networks (LAN and Docker) must be allowed")
    void testLocalNetworks() throws UnknownHostException {
        assertTrue(shield.isAllowed(InetAddress.getByName("192.168.1.100")));
        assertTrue(shield.isAllowed(InetAddress.getByName("10.5.0.1")));
        assertTrue(shield.isAllowed(InetAddress.getByName("172.20.0.2")));
    }

    @Test
    @DisplayName("Public internet IPs must be blocked in local-only mode")
    void testPublicIpsBlocked() throws UnknownHostException {
        assertFalse(shield.isAllowed(InetAddress.getByName("8.8.8.8")));
        assertFalse(shield.isAllowed(InetAddress.getByName("1.1.1.1")));
        assertFalse(shield.isAllowed(InetAddress.getByName("2606:4700:4700::1111")));
    }

    @Test
    @DisplayName("When local-only is false, all IPs must be allowed")
    void testLocalOnlyDisabled() throws UnknownHostException {
        NetworkShield openShield = new NetworkShield(false, List.of());
        assertTrue(openShield.isAllowed(InetAddress.getByName("8.8.8.8")));
    }
}
