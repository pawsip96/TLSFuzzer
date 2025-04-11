package org.fuzzer.message.parsers;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;

import java.util.ArrayList;
import java.util.List;

public class ServerHelloMessageParser {

    private final byte[] messageBytes;
    private ServerHelloMessage message;

    public ServerHelloMessageParser(byte[] messageBytes) {
        this.messageBytes = messageBytes;
        this.message = new ServerHelloMessage();
    }

    public ServerHelloMessage parse() {
        parseHandshakeMessageContent();
        return message;
    }

    private void parseHandshakeMessageContent() {
        int pointer = 0;

        // Parse Handshake Type
        message.setType(HandshakeMessageType.SERVER_HELLO.getValue());
        pointer += 1;

        // Parse Length
        int length = ArrayConverter.bytesToInt(
                new byte[]{0, messageBytes[pointer], messageBytes[pointer+1], messageBytes[pointer+2]}
        );
        message.setLength(length);
        pointer += 3;

        // Parse Protocol Version
        byte[] protocolVersionBytes = new byte[]{messageBytes[pointer], messageBytes[pointer+1]};
        message.setProtocolVersion(ProtocolVersion.getProtocolVersion(protocolVersionBytes).getValue());
        pointer += 2;

        // Parse Random (GMT Unix Time + Random Bytes)
        byte[] random = new byte[32];
        System.arraycopy(messageBytes, pointer, random, 0, 32);
        // Extract Unix Time (first 4 bytes of random)
        byte[] unixTimeBytes = new byte[]{random[0], random[1], random[2], random[3]};
        message.setUnixTime(unixTimeBytes);
        message.setRandom(random);
        pointer += 32;

        // Parse Session ID
        int sessionIdLength = messageBytes[pointer] & 0xFF;
        message.setSessionIdLength(sessionIdLength);
        pointer += 1;

        if (sessionIdLength > 0) {
            byte[] sessionId = new byte[sessionIdLength];
            System.arraycopy(messageBytes, pointer, sessionId, 0, sessionIdLength);
            message.setSessionId(sessionId);
            pointer += sessionIdLength;
        }

        // Parse Cipher Suite
        byte[] cipherSuiteBytes = new byte[]{messageBytes[pointer], messageBytes[pointer+1]};
        message.setSelectedCipherSuite(CipherSuite.getCipherSuite(cipherSuiteBytes).getByteValue());
        pointer += 2;

        // Parse Compression Method
        message.setSelectedCompressionMethod(CompressionMethod.getCompressionMethod(messageBytes[pointer]).getValue());
        pointer += 1;

        // Parse Extensions
        if (pointer < messageBytes.length && (pointer + 2) <= messageBytes.length) {
            int extensionsLength = ArrayConverter.bytesToInt(
                    new byte[]{0, messageBytes[pointer], messageBytes[pointer+1]}
            );
            message.setExtensionsLength(extensionsLength);
            pointer += 2;

            if (extensionsLength > 0 && (pointer + extensionsLength) <= messageBytes.length) {
                byte[] extensionBytes = new byte[extensionsLength];
                System.arraycopy(messageBytes, pointer, extensionBytes, 0, extensionsLength);
                message.setExtensionBytes(extensionBytes);

                // Parse extensions using the new parser
                ServerHelloExtensionsParser extensionsParser = new ServerHelloExtensionsParser(extensionBytes);
                List<ExtensionMessage> extensions = extensionsParser.parse();
                message.setExtensions(extensions);

                pointer += extensionsLength;
            }
        }
    }
}