package net.vafps.server;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.proxy.ProxyServer;
import net.vafps.audit.AuditLogger;
import net.vafps.execution.CapturingCommandSource;
import net.vafps.security.AccountConfig;
import net.vafps.security.AuthResult;
import net.vafps.security.Authenticator;
import net.vafps.security.NetworkShield;
import net.vafps.security.RateLimiter;
import net.vafps.server.dto.CommandResponse;
import net.vafps.server.dto.ErrorResponse;
import net.vafps.server.dto.HealthResponse;
import net.vafps.server.dto.StatusResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class VafpsHttpService {

    private static final Gson GSON = new Gson();
    private static final int MAX_BODY_BYTES = 8192;

    private final ProxyServer proxyServer;
    private final NetworkShield networkShield;
    private final Authenticator authenticator;
    private final RateLimiter rateLimiter;
    private final Set<String> dangerousCommands;
    private final int maxWaitMs;
    private final int outputSettleMs;
    private final int maxLines;
    private final Locale outputLocale;
    private final boolean logCommandArgs;
    private final long startedAt;

    private HttpServer httpServer;
    private ThreadPoolExecutor executor;

    public VafpsHttpService(ProxyServer proxyServer,
                            NetworkShield networkShield,
                            Authenticator authenticator,
                            List<String> dangerousCommands,
                            int maxWaitMs,
                            int outputSettleMs,
                            int maxLines,
                            Locale outputLocale,
                            boolean logCommandArgs) {
        this(proxyServer, networkShield, authenticator, new RateLimiter(networkShield), dangerousCommands,
                maxWaitMs, outputSettleMs, maxLines, outputLocale, logCommandArgs);
    }

    public VafpsHttpService(ProxyServer proxyServer,
                            NetworkShield networkShield,
                            Authenticator authenticator,
                            RateLimiter rateLimiter,
                            List<String> dangerousCommands,
                            int maxWaitMs,
                            int outputSettleMs,
                            int maxLines,
                            Locale outputLocale,
                            boolean logCommandArgs) {
        this.proxyServer = proxyServer;
        this.networkShield = networkShield;
        this.authenticator = authenticator;
        this.rateLimiter = rateLimiter != null ? rateLimiter : new RateLimiter(networkShield);
        this.dangerousCommands = new HashSet<>();
        if (dangerousCommands != null) {
            for (String cmd : dangerousCommands) {
                this.dangerousCommands.add(cmd.toLowerCase(Locale.ROOT));
            }
        }
        this.maxWaitMs = maxWaitMs;
        this.outputSettleMs = outputSettleMs;
        this.maxLines = maxLines;
        this.outputLocale = outputLocale != null ? outputLocale : Locale.US;
        this.logCommandArgs = logCommandArgs;
        this.startedAt = System.currentTimeMillis();
    }

    public synchronized void start(String host, int port) throws IOException {
        executor = new ThreadPoolExecutor(
                32, 32,
                60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(32),
                Executors.defaultThreadFactory(),
                (r, exec) -> {
                    // Pool/queue full -> 503 SERVICE_UNAVAILABLE
                    throw new RejectedExecutionException("Worker pool full");
                }
        );
        executor.allowCoreThreadTimeOut(true);

        httpServer = HttpServer.create(new InetSocketAddress(host, port), 0);
        httpServer.setExecutor(executor);

        httpServer.createContext("/api/v1/command", new CommandHandler());
        httpServer.createContext("/api/v1/status", new StatusHandler());
        httpServer.createContext("/api/v1/internal-health", new InternalHealthHandler());

        httpServer.start();
    }

    public synchronized void stop() {
        if (httpServer != null) {
            httpServer.stop(1);
            httpServer = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    public int getPort() {
        return httpServer != null ? httpServer.getAddress().getPort() : -1;
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    private void sendJson(HttpExchange exchange, int statusCode, Object body, boolean closeConnection) throws IOException {
        String json = GSON.toJson(body);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        if (closeConnection) {
            exchange.getResponseHeaders().set("Connection", "close");
        }
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private class CommandHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            InetAddress remoteAddress = exchange.getRemoteAddress().getAddress();

            // 1. Network Shield check
            if (!networkShield.isAllowed(remoteAddress)) {
                sendJson(exchange, 403, new ErrorResponse("NETWORK_DENIED", "Kaynak IP izin verilen ag araliginda degil."), true);
                return;
            }

            // 2. Method check
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, new ErrorResponse("METHOD_NOT_ALLOWED", "Yalnizca POST desteklenir."), false);
                return;
            }

            // 3. Media Type check
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
                sendJson(exchange, 415, new ErrorResponse("UNSUPPORTED_MEDIA_TYPE", "Content-Type application/json olmalidir."), false);
                return;
            }

            // 4. RateLimiter & Quarantine check
            RateLimiter.QuarantineAction action = rateLimiter.checkIp(remoteAddress);
            if (action == RateLimiter.QuarantineAction.QUARANTINED) {
                sendJson(exchange, 429, new ErrorResponse("TOO_MANY_REQUESTS", "Cok fazla basarisiz deneme. IP karantinaya alindi."), true);
                return;
            } else if (action == RateLimiter.QuarantineAction.TARPIT) {
                try {
                    Thread.sleep(rateLimiter.getTarpitDelayMs());
                } catch (InterruptedException ignored) {}
            }

            // 5. Authentication check
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            AuthResult authResult = authenticator.authenticate(authHeader, remoteAddress);
            if (!authResult.isAuthenticated()) {
                rateLimiter.recordAuthFailure(remoteAddress);
                exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"VAfPS\", charset=\"UTF-8\"");
                sendJson(exchange, 401, new ErrorResponse("UNAUTHORIZED", "Gecersiz kimlik bilgisi."), true);
                return;
            }
            rateLimiter.recordAuthSuccess(remoteAddress);

            AccountConfig account = authResult.getAccount();

            // 6. Read body with 8 KB limit
            String lengthHeader = exchange.getRequestHeaders().getFirst("Content-Length");
            if (lengthHeader != null) {
                try {
                    long len = Long.parseLong(lengthHeader);
                    if (len > MAX_BODY_BYTES) {
                        sendJson(exchange, 413, new ErrorResponse("PAYLOAD_TOO_LARGE", "Gövde 8 KB sınırını asamaz."), true);
                        return;
                    }
                } catch (NumberFormatException ignored) {}
            }

            byte[] bodyBytes;
            try (InputStream is = exchange.getRequestBody(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int read;
                int total = 0;
                while ((read = is.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_BODY_BYTES) {
                        sendJson(exchange, 413, new ErrorResponse("PAYLOAD_TOO_LARGE", "Gövde 8 KB sınırını asamaz."), true);
                        return;
                    }
                    baos.write(buffer, 0, read);
                }
                bodyBytes = baos.toByteArray();
            }

            String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);
            Map<?, ?> map;
            try {
                map = GSON.fromJson(bodyStr, Map.class);
            } catch (Exception e) {
                sendJson(exchange, 400, new ErrorResponse("BAD_REQUEST", "Gecersiz JSON."), false);
                return;
            }

            if (map == null || !(map.get("command") instanceof String rawCommand)) {
                sendJson(exchange, 400, new ErrorResponse("BAD_REQUEST", "command alani zorunludur ve metin olmalidir."), false);
                return;
            }

            // Validate control chars
            if (rawCommand.matches(".*[\\p{Cc}\\u0085\\u2028\\u2029].*")) {
                sendJson(exchange, 400, new ErrorResponse("BAD_REQUEST", "Komut metninde gecersiz kontrol karakterleri var."), false);
                return;
            }

            String trimmed = rawCommand.trim();
            if (trimmed.startsWith("/")) {
                trimmed = trimmed.substring(1).trim();
            }
            if (trimmed.isEmpty()) {
                sendJson(exchange, 400, new ErrorResponse("BAD_REQUEST", "Komut bos olamaz."), false);
                return;
            }

            String rootCommand = trimmed.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);

            // 7. Resolve command aliases and verify dangerous commands & account permission
            CommandManager commandManager = proxyServer.getCommandManager();
            CommandMeta meta = commandManager.getCommandMeta(rootCommand);
            if (meta == null && !commandManager.hasCommand(rootCommand)) {
                sendJson(exchange, 404, new ErrorResponse("UNKNOWN_COMMAND", "Komut proxy üzerinde kayitli degil."), false);
                return;
            }

            Set<String> aliases = new HashSet<>();
            aliases.add(rootCommand);
            if (meta != null && meta.getAliases() != null) {
                for (String alias : meta.getAliases()) {
                    aliases.add(alias.toLowerCase(Locale.ROOT));
                }
            }

            // Check dangerous commands
            boolean isDangerous = false;
            for (String alias : aliases) {
                if (dangerousCommands.contains(alias)) {
                    isDangerous = true;
                    break;
                }
            }

            if (isDangerous && !account.getCommands().contains("*")) {
                sendJson(exchange, 403, new ErrorResponse("COMMAND_DENIED", "Bu tehlikeli komut yalnizca * yetkisiyle calistirilabilir."), false);
                return;
            }

            // Check account permission
            boolean permitted = false;
            for (String alias : aliases) {
                if (account.hasPermission(alias)) {
                    permitted = true;
                    break;
                }
            }
            if (!permitted) {
                sendJson(exchange, 403, new ErrorResponse("COMMAND_DENIED", "Hesabin bu komutu calistirma yetkisi yok."), false);
                return;
            }

            // 8. Execute command and capture output
            long startTime = System.currentTimeMillis();
            CapturingCommandSource source = new CapturingCommandSource(maxLines, outputLocale);

            int configuredWait = account.getOutputWait();
            int effectiveWait = Math.min(configuredWait, maxWaitMs);

            CompletableFuture<Boolean> future = commandManager.executeAsync(source, trimmed);

            Boolean executed = null;
            boolean truncated = false;

            if (effectiveWait > 0) {
                try {
                    executed = future.get(effectiveWait, TimeUnit.MILLISECONDS);
                    long futureDoneTime = System.currentTimeMillis();

                    // Settle cycle
                    while (System.currentTimeMillis() - startTime < effectiveWait) {
                        long lastActivity = Math.max(source.getLastMessageTimestamp(), futureDoneTime);
                        if (System.currentTimeMillis() - lastActivity >= outputSettleMs) {
                            break;
                        }
                        try {
                            Thread.sleep(20);
                        } catch (InterruptedException ignored) {
                            break;
                        }
                    }
                } catch (TimeoutException e) {
                    truncated = true;
                    executed = null;
                } catch (Exception e) {
                    executed = false;
                }
            }

            source.close();
            long executionTime = System.currentTimeMillis() - startTime;

            String status = Boolean.FALSE.equals(executed) ? "NOT_EXECUTED" : "DISPATCHED";
            CommandResponse response = new CommandResponse(
                    status,
                    executed,
                    source.getBuffer(),
                    true,
                    truncated,
                    source.isLinesTruncated(),
                    executionTime
            );

            // Audit log
            String audit = AuditLogger.formatCommandLog(remoteAddress.getHostAddress(), account.getUsername(), trimmed, logCommandArgs, status);
            System.out.println(audit);

            sendJson(exchange, 200, response, false);
        }
    }

    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            InetAddress remoteAddress = exchange.getRemoteAddress().getAddress();
            if (!networkShield.isAllowed(remoteAddress)) {
                sendJson(exchange, 403, new ErrorResponse("NETWORK_DENIED", "Kaynak IP izin verilen ag araliginda degil."), true);
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, new ErrorResponse("METHOD_NOT_ALLOWED", "Yalnizca GET desteklenir."), false);
                return;
            }

            RateLimiter.QuarantineAction action = rateLimiter.checkIp(remoteAddress);
            if (action == RateLimiter.QuarantineAction.QUARANTINED) {
                sendJson(exchange, 429, new ErrorResponse("TOO_MANY_REQUESTS", "Cok fazla basarisiz deneme. IP karantinaya alindi."), true);
                return;
            } else if (action == RateLimiter.QuarantineAction.TARPIT) {
                try {
                    Thread.sleep(rateLimiter.getTarpitDelayMs());
                } catch (InterruptedException ignored) {}
            }

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            AuthResult authResult = authenticator.authenticate(authHeader, remoteAddress);
            if (!authResult.isAuthenticated()) {
                rateLimiter.recordAuthFailure(remoteAddress);
                exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"VAfPS\", charset=\"UTF-8\"");
                sendJson(exchange, 401, new ErrorResponse("UNAUTHORIZED", "Gecersiz kimlik bilgisi."), true);
                return;
            }
            rateLimiter.recordAuthSuccess(remoteAddress);

            StatusResponse statusResponse = new StatusResponse(
                    "ONLINE",
                    proxyServer.getVersion().getName() + " " + proxyServer.getVersion().getVersion(),
                    proxyServer.getPlayerCount()
            );
            sendJson(exchange, 200, statusResponse, false);
        }
    }

    private class InternalHealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            InetAddress remoteAddress = exchange.getRemoteAddress().getAddress();
            if (!networkShield.isAllowed(remoteAddress)) {
                sendJson(exchange, 403, new ErrorResponse("NETWORK_DENIED", "Kaynak IP izin verilen ag araliginda degil."), true);
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, new ErrorResponse("METHOD_NOT_ALLOWED", "Yalnizca GET desteklenir."), false);
                return;
            }

            int activeWorkers = executor != null ? executor.getActiveCount() : 0;
            int queueSize = executor != null ? executor.getQueue().size() : 0;
            long uptime = System.currentTimeMillis() - startedAt;

            HealthResponse healthResponse = new HealthResponse("OK", uptime, activeWorkers, queueSize);
            sendJson(exchange, 200, healthResponse, false);
        }
    }
}
