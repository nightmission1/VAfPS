package net.vafps.security;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Basic Auth validator with constant-time equality check and user enumeration protection.
 * Uses SHA-256 digested comparison to guarantee fixed length comparison (32 bytes)
 * and prevent timing attacks on password lengths.
 */
public class Authenticator {

    private static final byte[] FAKE_PASSWORD_HASH;

    static {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FAKE_PASSWORD_HASH = digest.digest("vafps_constant_dummy_password_hash_salt_xyz".getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private final Map<String, AccountConfig> accounts = new ConcurrentHashMap<>();
    private final boolean rootPermanentlyDisabled;

    public Authenticator(Map<String, AccountConfig> initialAccounts, boolean rootPermanentlyDisabled) {
        this.rootPermanentlyDisabled = rootPermanentlyDisabled;
        if (initialAccounts != null) {
            initialAccounts.forEach((name, acc) -> this.accounts.put(name, acc.withUsername(name)));
        }
    }

    public AuthResult authenticate(String authHeader, InetAddress remoteAddress) {
        if (authHeader == null || authHeader.length() > 256 || !authHeader.startsWith("Basic ")) {
            return AuthResult.failure("unknown");
        }

        String base64Credentials = authHeader.substring(6).trim();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Credentials);
        } catch (IllegalArgumentException e) {
            return AuthResult.failure("invalid_base64");
        }

        String credentials = new String(decoded, StandardCharsets.UTF_8);
        int colonIndex = credentials.indexOf(':');
        if (colonIndex == -1) {
            return AuthResult.failure("invalid_format");
        }

        String username = credentials.substring(0, colonIndex);
        String password = credentials.substring(colonIndex + 1);

        AccountConfig account = accounts.get(username);

        // Constant-time check and user enumeration protection via SHA-256 digest
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }

        byte[] providedPasswordHash = sha256.digest(password.getBytes(StandardCharsets.UTF_8));
        byte[] actualPasswordHash;
        if (account != null) {
            try {
                MessageDigest innerDigest = MessageDigest.getInstance("SHA-256");
                actualPasswordHash = innerDigest.digest(account.getPassword().getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                actualPasswordHash = FAKE_PASSWORD_HASH;
            }
        } else {
            actualPasswordHash = FAKE_PASSWORD_HASH;
        }

        // Both providedPasswordHash and actualPasswordHash are guaranteed to be 32 bytes
        boolean matches = MessageDigest.isEqual(providedPasswordHash, actualPasswordHash);

        if (account == null || !matches) {
            return AuthResult.failure(username);
        }

        // Special handling for root account
        if ("root".equalsIgnoreCase(username)) {
            if (rootPermanentlyDisabled) {
                return AuthResult.failure(username);
            }
            InetAddress normalized = NetworkShield.normalize(remoteAddress);
            if (!normalized.isLoopbackAddress()) {
                return AuthResult.failure(username);
            }
        }

        return AuthResult.success(account);
    }
}
