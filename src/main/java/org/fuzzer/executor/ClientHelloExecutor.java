package org.fuzzer.executor;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.fuzzer.message.parsers.ServerHelloMessageParser;
import org.fuzzer.message.parsers.TLSHeaderParser;
import org.fuzzer.message.peparators.ClientHelloMessage;

import java.io.IOException;
import java.util.Arrays;

public class ClientHelloExecutor {

    private ClientHelloMessage clientHelloMessage;
    private TLSHeaderParser tlsHeaderParser;

    public ClientHelloExecutor(ClientHelloMessage clientHelloMessage) {
        this.clientHelloMessage = clientHelloMessage;
    }

    private static final Logger LOGGER = LogManager.getLogger(ClientHelloExecutor.class);

    public void executeTest() {
        try {
            // Execute ClientHello message
            ClientHelloHandler executor = new ClientHelloHandler(clientHelloMessage);
            executor.executeMessage();
            byte[] response = executor.getResponse();

            // Parse the response with TLSHeaderParser
            this.tlsHeaderParser = new TLSHeaderParser(response);

            // Print parsed response details
            System.out.println("Content Type: " + tlsHeaderParser.getContentType());
            System.out.println("Version: " + tlsHeaderParser.getVersion());
            System.out.println("Length: " + tlsHeaderParser.getLength());
            System.out.println("Message Content: " + Arrays.toString(tlsHeaderParser.getMessageContent()));

        } catch (IOException e) {
            System.err.println("Error executing ClientHello message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Error parsing TLS response: " + e.getMessage());
        }
    }

    public TLSHeaderParser getTlsHeaderParser(){
        return this.tlsHeaderParser;
    }
}
