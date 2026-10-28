package net.vafps.execution;

import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class CapturingCommandSourceTest {

    @Test
    @DisplayName("CapturingCommandSource captures messages and renders plain text")
    void testMessageCapture() {
        CapturingCommandSource source = new CapturingCommandSource(10, Locale.US);
        source.sendMessage(Component.text("Line 1\nLine 2"));

        List<String> buffer = source.getBuffer();
        assertEquals(2, buffer.size());
        assertEquals("Line 1", buffer.get(0));
        assertEquals("Line 2", buffer.get(1));
        assertFalse(source.isLinesTruncated());
        assertTrue(source.getLastMessageTimestamp() > 0);
    }

    @Test
    @DisplayName("CapturingCommandSource truncates lines when exceeding maxLines")
    void testLineTruncation() {
        CapturingCommandSource source = new CapturingCommandSource(2, Locale.US);
        source.sendMessage(Component.text("Line 1\nLine 2\nLine 3"));

        List<String> buffer = source.getBuffer();
        assertEquals(2, buffer.size());
        assertTrue(source.isLinesTruncated());
    }

    @Test
    @DisplayName("Closed CapturingCommandSource ignores subsequent messages")
    void testClosedSource() {
        CapturingCommandSource source = new CapturingCommandSource(10, Locale.US);
        source.sendMessage(Component.text("Initial"));
        source.close();
        source.sendMessage(Component.text("Ignored"));

        List<String> buffer = source.getBuffer();
        assertEquals(1, buffer.size());
        assertEquals("Initial", buffer.get(0));
    }
}
