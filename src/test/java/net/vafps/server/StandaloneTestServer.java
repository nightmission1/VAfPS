package net.vafps.server;

import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.util.ProxyVersion;
import net.kyori.adventure.text.Component;
import net.vafps.security.AccountConfig;
import net.vafps.security.Authenticator;
import net.vafps.security.NetworkShield;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Bağımsız çalıştırılabilir VAfPS Test HTTP Sunucusu (Standalone Mock Test Server).
 * Test ve güvenlik simülasyonları için kullanılır.
 */
public class StandaloneTestServer {

    public static void main(String[] args) throws IOException {
        int port = 8923;
        String host = "127.0.0.1";

        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }

        // Mock ProxyServer ve CommandManager
        ProxyServer mockProxy = Mockito.mock(ProxyServer.class);
        CommandManager mockCmdMgr = Mockito.mock(CommandManager.class);
        ProxyVersion mockVersion = Mockito.mock(ProxyVersion.class);

        when(mockProxy.getCommandManager()).thenReturn(mockCmdMgr);
        when(mockProxy.getVersion()).thenReturn(mockVersion);
        when(mockProxy.getPlayerCount()).thenReturn(3);
        when(mockVersion.getName()).thenReturn("Velocity-TestEnvironment");
        when(mockVersion.getVersion()).thenReturn("3.4.0");

        // Örnek komutlar tanımla
        List<String> mockCommands = List.of("alert", "kick", "send", "glist", "find", "end", "shutdown");
        for (String cmd : mockCommands) {
            when(mockCmdMgr.hasCommand(cmd)).thenReturn(true);
        }

        // Komut yürütme davranışı
        when(mockCmdMgr.executeAsync(any(), anyString())).thenAnswer(invocation -> {
            CommandSource source = invocation.getArgument(0);
            String commandLine = invocation.getArgument(1);
            source.sendMessage(Component.text("[Sunucu Çıktısı] Komut başarıyla işlendi: " + commandLine));
            return CompletableFuture.completedFuture(true);
        });

        // NetworkShield (Loopback ve yerel ağ)
        NetworkShield shield = new NetworkShield(true, List.of(
                "127.0.0.0/8", "::1/128", "192.168.0.0/16", "10.0.0.0/8"
        ));

        // Hesaplar
        Map<String, AccountConfig> accounts = new HashMap<>();
        accounts.put("root", new AccountConfig("abcd1234", List.of("*"), 1000));
        accounts.put("paper_backend", new AccountConfig("PaperSecret987!", List.of("alert", "kick", "send"), 1000));
        accounts.put("readonly_bot", new AccountConfig("ViewerPass321!", List.of("glist", "find"), 500));

        Authenticator authenticator = new Authenticator(accounts, false);

        VafpsHttpService service = new VafpsHttpService(
                mockProxy,
                shield,
                authenticator,
                List.of("end", "shutdown", "velocity"),
                5000,
                150,
                200,
                Locale.US,
                true
        );

        service.start(host, port);
        int boundPort = service.getPort();

        System.out.println("======================================================");
        System.out.println(" [VAfPS] Test Sunucusu Başlatıldı!");
        System.out.println(" Adres: http://" + host + ":" + boundPort);
        System.out.println(" Aktif Hesaplar:");
        System.out.println("   - root:abcd1234 (Tüm komutlar '*')");
        System.out.println("   - paper_backend:PaperSecret987! (alert, kick, send)");
        System.out.println("   - readonly_bot:ViewerPass321! (glist, find)");
        System.out.println(" Endpoints:");
        System.out.println("   - GET  /api/v1/status");
        System.out.println("   - POST /api/v1/command");
        System.out.println("======================================================");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[VAfPS] Test sunucusu kapatılıyor...");
            service.stop();
        }));
    }
}
