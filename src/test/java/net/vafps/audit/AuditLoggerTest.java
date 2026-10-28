package net.vafps.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLoggerTest {

    @Test
    @DisplayName("ANSI escape codes and control characters must be removed")
    void testAnsiAndControlCharsSanitized() {
        String dirty = "\u001B[31mRed Alert!\u001B[0m\u0007\r\n";
        String clean = AuditLogger.sanitize(dirty);
        assertFalse(clean.contains("\u001B"));
        assertFalse(clean.contains("\u0007"));
        assertTrue(clean.contains("Red Alert!"));
    }

    @Test
    @DisplayName("Arguments must be masked when logArgs is false")
    void testMaskCommandArgs() {
        String log = AuditLogger.formatCommandLog("127.0.0.1", "admin", "ban Steve 7d", false, "DISPATCHED");
        assertTrue(log.contains("\"ban ***\""));
        assertFalse(log.contains("Steve"));
        assertTrue(log.contains("DISPATCHED"));
    }
}
