package emu.reader;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RealPassportReaderTaskTest {

    @Test
    void optionalFileReadReturnsNullWhenMissing() {
        List<String> messages = new ArrayList<>();
        List<String> labels = List.of("DG14", "DG15", "EF.COM", "EF.SOD", "EF.CardAccess");

        for (String label : labels) {
            byte[] bytes = RealPassportReaderTask.readOptionalFile(
                    () -> {
                        throw new IOException("missing " + label);
                    },
                    messages::add,
                    label);
            assertNull(bytes, label + " should be absent");
        }

        assertEquals(labels.size(), messages.size(), "Each missing file should produce a log message");
        for (int i = 0; i < labels.size(); i++) {
            String label = labels.get(i);
            String message = messages.get(i);
            assertTrue(message.contains(label), "Message should reference label: " + label);
        }
    }

    @Test
    void optionalFileReadReturnsContentWhenPresent() throws Exception {
        byte[] expected = new byte[] {0x01, 0x23, (byte) 0xFF};
        byte[] bytes = RealPassportReaderTask.readOptionalFile(
                () -> new ByteArrayInputStream(expected),
                null,
                "DG14");
        assertArrayEquals(expected, bytes);
    }
}
