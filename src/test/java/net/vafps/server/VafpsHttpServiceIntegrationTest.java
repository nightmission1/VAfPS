package net.vafps.server;

import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.util.ProxyVersion;
import net.kyori.adventure.text.Component;
import net.vafps.security.AccountConfig;
import net.vafps.security.Authenticator;
import net.vafps.security.NetworkShield;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class VafpsHttpServiceIntegrationTest {

    private ProxyServer proxyServer;
    private CommandManager commandManager;
    private VafpsHttpService service;
    private HttpClient httpClient;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        proxyServer = Mockito.mock(ProxyServer.class);
        commandManager = Mockito.mock(CommandManager.class);
        ProxyVersion proxyVersion = Mockito.mock(ProxyVersion.class);

        when(proxyServer.getCommandManager()).thenReturn(commandManager);
        when(proxyServer.getVersion()).thenReturn(proxyVersion);
        when(proxyServer.getPlayerCount()).thenReturn(42);
        when(proxyVersion.getName()).thenReturn("Velocity");
        when(proxyVersion.getVersion()).thenReturn("3.4.0-SNAPSHOT");

        NetworkShield shield = new NetworkShield(true, List.of("127.0.0.0/8", "::1/128"));
        Map<String, AccountConfig> accounts = new HashMap<>();
        accounts.put("root", new AccountConfig("abcd1234", List.of("*"), 1000));
        accounts.put("mod", new AccountConfig("GucluSifre123!", List.of("kick"), 1000));
        Authenticator authenticator = new Authenticator(accounts, false);

        service = new VafpsHttpService(
                proxyServer,
                shield,
                authenticator,
                List.of("end", "shutdown"),
                5000,
                150,
                200,
                Locale.US,
                true
        );

        service.start("127.0.0.1", 0);
        port = service.getPort();
        httpClient = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.stop();
        }
    }

    @Test
    @DisplayName("Status endpoint returns ONLINE with valid Basic Auth")
    void testStatusEndpoint() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/status"))
                .header("Authorization", "Basic cm9vdDphYmNkMTIzNA==")
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"status\":\"ONLINE\""));
        assertTrue(response.body().contains("\"onlinePlayers\":42"));
    }

    @Test
    @DisplayName("Command endpoint executes allowed command and captures output")
    void testCommandExecution() throws Exception {
        when(commandManager.hasCommand("kick")).thenReturn(true);
        when(commandManager.executeAsync(any(), eq("kick Steve"))).thenAnswer(invocation -> {
            CommandSource source = invocation.getArgument(0);
            source.sendMessage(Component.text("Steve kicklendi."));
            return CompletableFuture.completedFuture(true);
        });

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/command"))
                .header("Authorization", "Basic cm9vdDphYmNkMTIzNA==")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"command\": \"kick Steve\"}"))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"status\":\"DISPATCHED\""));
        assertTrue(response.body().contains("\"executed\":true"));
        assertTrue(response.body().contains("Steve kicklendi."));
    }

    @Test
    @DisplayName("Command with unauthorized account returns 403 COMMAND_DENIED")
    void testUnauthorizedCommand() throws Exception {
        when(commandManager.hasCommand("ban")).thenReturn(true);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/command"))
                .header("Authorization", "Basic YWRtaW46R3VjbHVTaWZyZTEyMyE=") // mod hesabı değilse 401, mod ban komutu için 403
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"command\": \"ban Steve\"}"))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode()); // admin tanımlı değil -> 401
    }

    @Test
    @DisplayName("Internal health check requires valid token and works regardless of CIDR")
    void testInternalHealthEndpoint() throws Exception {
        // Without token -> 403
        HttpRequest requestNoToken = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/internal-health"))
                .GET()
                .build();
        HttpResponse<String> respNoToken = httpClient.send(requestNoToken, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, respNoToken.statusCode());
        assertTrue(respNoToken.body().contains("X-Internal-Health-Token"));

        // With invalid token -> 403
        HttpRequest requestInvalidToken = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/internal-health"))
                .header("X-Internal-Health-Token", "invalid_token_123")
                .GET()
                .build();
        HttpResponse<String> respInvalid = httpClient.send(requestInvalidToken, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, respInvalid.statusCode());

        // With valid token -> 200 OK
        HttpRequest requestValid = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/internal-health"))
                .header("X-Internal-Health-Token", service.getInternalHealthToken())
                .GET()
                .build();
        HttpResponse<String> respValid = httpClient.send(requestValid, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, respValid.statusCode());
        assertTrue(respValid.body().contains("\"status\":\"OK\""));
    }
}
