package net.vafps.execution;

import com.velocitypowered.api.proxy.ConsoleCommandSource;
import com.velocitypowered.api.permission.Tristate;
import net.kyori.adventure.identity.Identity;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.kyori.adventure.translation.GlobalTranslator;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Custom ConsoleCommandSource capturing console outputs with line filters,
 * truncation flags, and timestamps for settle windows.
 */
public class CapturingCommandSource implements ConsoleCommandSource {

    private final List<String> buffer = new CopyOnWriteArrayList<>();
    private final AtomicInteger lineCount = new AtomicInteger(0);
    private final int maxLines;
    private final Locale outputLocale;
    private volatile boolean closed = false;
    private volatile boolean linesTruncated = false;
    private volatile long lastMessageTimestamp = 0;

    public CapturingCommandSource(int maxLines, Locale outputLocale) {
        this.maxLines = maxLines;
        this.outputLocale = outputLocale != null ? outputLocale : Locale.US;
    }

    @Override
    public void sendMessage(Identity identity, Component message) {
        capture(message);
    }

    @Override
    public void sendMessage(Component message) {
        capture(message);
    }

    private void capture(Component message) {
        if (closed || message == null) return;

        Component rendered = GlobalTranslator.render(message, outputLocale);
        String plain = PlainTextComponentSerializer.plainText().serialize(rendered);

        String[] lines = plain.split("\\r?\\n", -1);
        for (String line : lines) {
            // Trim whitespace check: completely blank lines are filtered if multiple lines
            if (line.trim().isEmpty() && lines.length > 1) {
                continue;
            }
            if (lineCount.incrementAndGet() > maxLines) {
                linesTruncated = true;
                break;
            }
            buffer.add(line);
            lastMessageTimestamp = System.currentTimeMillis();
        }
    }

    @Override
    public Tristate getPermissionValue(String permission) {
        return Tristate.TRUE;
    }

    public void close() {
        this.closed = true;
    }

    public List<String> getBuffer() {
        return new ArrayList<>(buffer);
    }

    public boolean isLinesTruncated() {
        return linesTruncated;
    }

    public long getLastMessageTimestamp() {
        return lastMessageTimestamp;
    }
}
