package net.vafps.security;

public class AuthResult {
    private final boolean authenticated;
    private final AccountConfig account;
    private final String attemptedUsername;

    public AuthResult(boolean authenticated, AccountConfig account, String attemptedUsername) {
        this.authenticated = authenticated;
        this.account = account;
        this.attemptedUsername = attemptedUsername;
    }

    public static AuthResult success(AccountConfig account) {
        return new AuthResult(true, account, account.getUsername());
    }

    public static AuthResult failure(String attemptedUsername) {
        return new AuthResult(false, null, attemptedUsername);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public AccountConfig getAccount() {
        return account;
    }

    public String getAttemptedUsername() {
        return attemptedUsername;
    }
}
