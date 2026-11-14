package net.vafps;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import net.vafps.security.AccountConfig;
import net.vafps.security.Authenticator;
import net.vafps.security.NetworkShield;
import net.vafps.server.VafpsHttpService;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Plugin(
        id = "vafps",
        name = "VAfPS",
        version = "2.7.0",
        description = "Velocity API for Paper Server",
        authors = {"NightMission"}
)
public class VafpsPlugin {

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Path dataDirectory;
    private VafpsHttpService httpService;

    @Inject
    public VafpsPlugin(ProxyServer proxyServer, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxyServer = proxyServer;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory);
            }

            Path rootDisabledFile = dataDirectory.resolve(".root_disabled");
            boolean rootDisabled = Files.exists(rootDisabledFile);

            // Default PnP configuration
            NetworkShield shield = new NetworkShield(true, List.of(
                    "127.0.0.0/8", "::1/128", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "fc00::/7", "fe80::/10"
            ));

            Map<String, AccountConfig> accounts = new HashMap<>();
            accounts.put("root", new AccountConfig("abcd1234", List.of("*"), 1000));

            if (!rootDisabled) {
                logger.warn("[VAfPS-WARN] Varsayilan 'root' hesabi aktiftir. Guvenliginiz icin config.yml icinde ozel bir hesap olusturunuz!");
            }

            Authenticator authenticator = new Authenticator(accounts, rootDisabled);

            httpService = new VafpsHttpService(
                    proxyServer,
                    shield,
                    authenticator,
                    List.of("end", "shutdown", "velocity"),
                    5000,
                    150,
                    200,
                    Locale.US,
                    true
            );

            httpService.start("127.0.0.1", 8923);
            logger.info("[VAfPS] HTTP API köprüsü 127.0.0.1:8923 üzerinde basariyla baslatildi.");
        } catch (IOException e) {
            logger.error("[VAfPS-ERROR] API baslatilamadi! Port cakismasi veya ag hatasi.", e);
            proxyServer.shutdown();
        }
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (httpService != null) {
            httpService.stop();
            logger.info("[VAfPS] HTTP API durduruldu.");
        }
    }
}
