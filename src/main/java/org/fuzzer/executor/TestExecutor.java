package org.fuzzer.executor;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import org.fuzzer.message.parsers.ServerHelloMessageParser;
import org.fuzzer.message.parsers.TLSHeaderParser;
import org.fuzzer.message.peparators.ClientHelloMessage;
import java.io.IOException;
import java.util.Arrays;

public class TestExecutor {

    private ClientHelloMessage clientHelloMessage;

    public TestExecutor(ClientHelloMessage clientHelloMessage) {
        this.clientHelloMessage = clientHelloMessage;
    }

    public void executeTest() {
        try {
            // Execute ClientHello message
            ClientHelloExecutor executor = new ClientHelloExecutor(clientHelloMessage);
            executor.executeMessage();
            byte[] response = executor.getResponse();

            // Parse the response with TLSHeaderParser
            TLSHeaderParser parser = new TLSHeaderParser(response);

            // Print parsed response details
            System.out.println("Content Type: " + parser.getContentType());
            System.out.println("Version: " + parser.getVersion());
            System.out.println("Length: " + parser.getLength());
            System.out.println("Message Content: " + Arrays.toString(parser.getMessageContent()));

        } catch (IOException e) {
            System.err.println("Error executing ClientHello message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Error parsing TLS response: " + e.getMessage());
        }
    }
}
