package org.fuzzer.message.parsers;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class TLSHeaderParser {

    private static final int HEADER_LENGTH = 5; // TLS Record Layer header size
    private ProtocolVersion version;
    private int length;
    private ProtocolMessageType protocolMessageType;
    private byte[] messageContent;
    private HandshakeMessageType handshakeMessageType;


    public TLSHeaderParser(byte[] message) {
        if (message.length < HEADER_LENGTH) {
            throw new IllegalArgumentException("Invalid TLS message: too short");
        }
        parseHeader(message);
        extractContent(message);
    }

    private void parseHeader(byte[] message) {
        ByteBuffer buffer = ByteBuffer.wrap(message);
        byte contentType = buffer.get(); // First byte: Content Type
        short protocolVersion = buffer.getShort(); // Next two bytes: Protocol Version
        length = buffer.getShort() & 0xFFFF; // Last two bytes: Length (convert unsigned short)
        version = ProtocolVersion.getProtocolVersion(new byte[]{(byte) (protocolVersion >> 8), (byte) protocolVersion});
        protocolMessageType = ProtocolMessageType.getContentType(contentType);
    }

    private void extractContent(byte[] message) {
        if (length > 0) {
            messageContent = Arrays.copyOfRange(message, HEADER_LENGTH, HEADER_LENGTH + length);
            handshakeMessageType = HandshakeMessageType.getMessageType(messageContent[0]);
        } else {
            messageContent = new byte[0];
        }
    }

    public ProtocolMessageType getContentType() {
        return protocolMessageType;
    }
    public HandshakeMessageType getHandshakeMessageType(){
        return handshakeMessageType;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public int getLength() {
        return length;
    }

    public byte[] getMessageContent() {
        return messageContent;
    }
}

