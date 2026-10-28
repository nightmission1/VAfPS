package net.vafps.server.dto;

import java.util.List;

public class CommandResponse {
    private final String status;
    private final Boolean executed;
    private final List<String> output;
    private final Boolean captureEnabled;
    private final Boolean truncated;
    private final Boolean linesTruncated;
    private final Long executionTimeMs;

    public CommandResponse(String status, Boolean executed, List<String> output,
                           Boolean captureEnabled, Boolean truncated, Boolean linesTruncated, Long executionTimeMs) {
        this.status = status;
        this.executed = executed;
        this.output = output;
        this.captureEnabled = captureEnabled;
        this.truncated = truncated;
        this.linesTruncated = linesTruncated;
        this.executionTimeMs = executionTimeMs;
    }

    public String getStatus() { return status; }
    public Boolean getExecuted() { return executed; }
    public List<String> getOutput() { return output; }
    public Boolean getCaptureEnabled() { return captureEnabled; }
    public Boolean getTruncated() { return truncated; }
    public Boolean getLinesTruncated() { return linesTruncated; }
    public Long getExecutionTimeMs() { return executionTimeMs; }
}
