package org.fuzzer.message.parsers;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class TLSHeaderParserTest {

    @Test
    public void testValidTLSMessage() {
        byte[] exampleMessage = new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x06};
        TLSHeaderParser parser = new TLSHeaderParser(exampleMessage);

        assertEquals("ALERT", parser.getContentType().name());
        assertEquals("TLS12", parser.getVersion().name());
        assertEquals(2, parser.getLength());
        assertArrayEquals(new byte[]{0x02, 0x06}, parser.getMessageContent());
    }

    @Test
    public void testInvalidShortMessage() {
        byte[] shortMessage = new byte[]{0x15, 0x03};
        Exception exception = assertThrows(IllegalArgumentException.class, () -> new TLSHeaderParser(shortMessage));
        assertEquals("Invalid TLS message: too short", exception.getMessage());
    }
}
