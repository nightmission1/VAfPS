package net.vafps.server.dto;

public class StatusResponse {
    private final String status;
    private final String version;
    private final int onlinePlayers;

    public StatusResponse(String status, String version, int onlinePlayers) {
        this.status = status;
        this.version = version;
        this.onlinePlayers = onlinePlayers;
    }

    public String getStatus() { return status; }
    public String getVersion() { return version; }
    public int getOnlinePlayers() { return onlinePlayers; }
}
