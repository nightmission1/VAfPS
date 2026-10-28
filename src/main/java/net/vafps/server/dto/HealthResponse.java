package net.vafps.server.dto;

public class HealthResponse {
    private final String status;
    private final long uptimeMs;
    private final int activeWorkers;
    private final int queueSize;

    public HealthResponse(String status, long uptimeMs, int activeWorkers, int queueSize) {
        this.status = status;
        this.uptimeMs = uptimeMs;
        this.activeWorkers = activeWorkers;
        this.queueSize = queueSize;
    }

    public String getStatus() { return status; }
    public long getUptimeMs() { return uptimeMs; }
    public int getActiveWorkers() { return activeWorkers; }
    public int getQueueSize() { return queueSize; }
}
