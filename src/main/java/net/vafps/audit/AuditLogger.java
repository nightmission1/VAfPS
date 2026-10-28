package net.vafps.audit;

/**
 * Utility to sanitize terminal injection, ANSI escape codes, and format audit logs.
 */
public class AuditLogger {

    public static String sanitize(String input) {
        if (input == null) return "";
        // Strip ANSI escape codes
        String noAnsi = input.replaceAll("\\u001B\\[[;\\d]*[ -/]*[@-~]", "");
        // Strip control characters except standard space
        return noAnsi.replaceAll("[\\p{Cc}\\u0085\\u2028\\u2029]", "");
    }

    public static String formatCommandLog(String ip, String account, String command, boolean logArgs, String status) {
        String cleanIp = sanitize(ip);
        String cleanAccount = sanitize(account);
        String sanitizedCommand = sanitize(command);

        String loggedCommand;
        if (!logArgs && sanitizedCommand.contains(" ")) {
            String root = sanitizedCommand.split("\\s+", 2)[0];
            loggedCommand = root + " ***";
        } else {
            loggedCommand = sanitizedCommand;
        }

        return String.format("[VAfPS-LOG] [%d] [%s] [%s] - \"%s\" -> %s",
                System.currentTimeMillis(), cleanIp, cleanAccount, loggedCommand, status);
    }
}
