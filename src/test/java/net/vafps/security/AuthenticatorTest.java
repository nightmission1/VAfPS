package net.vafps.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticatorTest {

    private Authenticator authenticator;
    private Map<String, AccountConfig> accounts;

    @BeforeEach
    void setUp() {
        accounts = new HashMap<>();
        // root hesabı (yalnızca loopback geçerli)
        accounts.put("root", new AccountConfig("abcd1234", List.of("*"), 1000));
        // özel hesap
        accounts.put("admin", new AccountConfig("GucluSifre123!", List.of("ban", "kick"), 1500));

        authenticator = new Authenticator(accounts, false);
    }

    @Test
    @DisplayName("Root account should be allowed only from loopback")
    void testRootAccountFromLoopback() throws UnknownHostException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        AuthResult result = authenticator.authenticate("Basic cm9vdDphYmNkMTIzNA==", loopback); // root:abcd1234
        assertTrue(result.isAuthenticated());
        assertEquals("root", result.getAccount().getUsername());

        InetAddress remote = InetAddress.getByName("192.168.1.50");
        AuthResult remoteResult = authenticator.authenticate("Basic cm9vdDphYmNkMTIzNA==", remote);
        assertFalse(remoteResult.isAuthenticated());
    }

    @Test
    @DisplayName("Root account must be permanently disabled if .root_disabled flag is set")
    void testRootDisabledFlag() throws UnknownHostException {
        Authenticator disabledRootAuth = new Authenticator(accounts, true);
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        AuthResult result = disabledRootAuth.authenticate("Basic cm9vdDphYmNkMTIzNA==", loopback);
        assertFalse(result.isAuthenticated());
    }

    @Test
    @DisplayName("Custom account should authenticate with correct credentials from any network")
    void testCustomAccount() throws UnknownHostException {
        InetAddress remote = InetAddress.getByName("192.168.1.50");
        // admin:GucluSifre123! -> YWRtaW46R3VjbHVTaWZyZTEyMyE=
        AuthResult result = authenticator.authenticate("Basic YWRtaW46R3VjbHVTaWZyZTEyMyE=", remote);
        assertTrue(result.isAuthenticated());
        assertEquals("admin", result.getAccount().getUsername());
    }

    @Test
    @DisplayName("Invalid credentials or header length exceeding 256 chars must fail")
    void testInvalidCredentialsAndHeaderOverflow() throws UnknownHostException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        AuthResult wrongPass = authenticator.authenticate("Basic YWRtaW46WWFubGlzU2lmcmU=", loopback);
        assertFalse(wrongPass.isAuthenticated());

        String longHeader = "Basic " + "a".repeat(260);
        AuthResult overflow = authenticator.authenticate(longHeader, loopback);
        assertFalse(overflow.isAuthenticated());
    }
}
