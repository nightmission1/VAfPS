package net.vafps.security;

import java.util.List;

public class AccountConfig {
    private final String username;
    private final String password;
    private final List<String> commands;
    private final int outputWait;

    public AccountConfig(String password, List<String> commands, int outputWait) {
        this("", password, commands, outputWait);
    }

    public AccountConfig(String username, String password, List<String> commands, int outputWait) {
        this.username = username;
        this.password = password;
        this.commands = commands != null ? commands : List.of();
        this.outputWait = outputWait;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public List<String> getCommands() {
        return commands;
    }

    public int getOutputWait() {
        return outputWait;
    }

    public AccountConfig withUsername(String name) {
        return new AccountConfig(name, this.password, this.commands, this.outputWait);
    }

    public boolean hasPermission(String rootCommand) {
        if (commands.contains("*")) {
            return true;
        }
        for (String cmd : commands) {
            if (cmd.equalsIgnoreCase(rootCommand)) {
                return true;
            }
        }
        return false;
    }
}
