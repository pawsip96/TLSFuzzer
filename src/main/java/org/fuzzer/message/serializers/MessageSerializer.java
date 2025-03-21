package org.fuzzer.message.serializers;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class MessageSerializer {
    public static byte[] serializeMessage(byte[] handshakeMessage) {
        // TLS Record Header structure:
        // 1 byte: Record Type (0x16 for Handshake)
        // 2 bytes: Protocol Version (e.g., TLS 1.2 = 0x0303)
        // 2 bytes: Length of the handshake message

        byte[] recordHeader = new byte[5];
        recordHeader[0] = 0x16; // Handshake record type
        recordHeader[1] = 0x03;
        recordHeader[2] = 0x03;
        recordHeader[3] = (byte) ((handshakeMessage.length >> 8) & 0xFF); // Length (high byte)
        recordHeader[4] = (byte) (handshakeMessage.length & 0xFF); // Length (low byte)

        // Combine the record header and handshake message
        byte[] tlsRecord = new byte[recordHeader.length + handshakeMessage.length];
        System.arraycopy(recordHeader, 0, tlsRecord, 0, recordHeader.length);
        System.arraycopy(handshakeMessage, 0, tlsRecord, recordHeader.length, handshakeMessage.length);

        return tlsRecord;
    }
}
