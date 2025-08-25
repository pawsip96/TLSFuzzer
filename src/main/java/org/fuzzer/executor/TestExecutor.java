package org.fuzzer.executor;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.fuzzer.crypto.KeyLogWriter;
import org.fuzzer.message.parsers.ServerHelloMessageParser;
import org.fuzzer.message.parsers.TLSHeaderParser;
import org.fuzzer.message.peparators.ClientHelloMessage;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class TestExecutor {

    private ClientHelloMessage clientHelloMessage;

    public TestExecutor(ClientHelloMessage clientHelloMessage) {
        this.clientHelloMessage = clientHelloMessage;
    }

    private static final Logger LOGGER = LogManager.getLogger(TestExecutor.class);

    static {
        // Programmatically set logging level
        Configurator.setLevel("org.fuzzer", Level.DEBUG);
        Configurator.setLevel("de.rub.nds.tlsattacker", Level.DEBUG);
        Configurator.setRootLevel(Level.INFO);
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

            byte[] messageContent = parser.getMessageContent();
            ServerHelloMessageParser serverHelloParser = new ServerHelloMessageParser(messageContent);
            ServerHelloMessage serverHelloMessage = serverHelloParser.parse();
            serverHelloMessage.setSessionId(new byte[2]);
            System.out.println(serverHelloMessage.toString());

            Config config = Config.createConfig();

            BigInteger privateKey = config.getKeySharePrivate();
            NamedGroup namedGroup = NamedGroup.SECP256R1;

            KeyShareExtensionMessage extensionMessage = (KeyShareExtensionMessage) serverHelloMessage.getExtensions().get(1);
            byte[] publicKey = extensionMessage.getKeyShareList().get(0).getPublicKey().getValue();


            // 1. Shared secret already computed
            byte[] sharedSecret = KeyShareCalculator.computeSharedSecret(namedGroup, privateKey, publicKey);

            System.out.println("Shared Secret: ");
            System.out.println(Arrays.toString(sharedSecret));

            TlsContext tlsContext = new TlsContext();

            ServerHelloHandler serverHelloHandler = new ServerHelloHandler(tlsContext);
            serverHelloHandler.adjustTLSContext(serverHelloMessage);

            KeyLogWriter keylogwriter = new KeyLogWriter(tlsContext, "keys.log");



        } catch (IOException e) {
            System.err.println("Error executing ClientHello message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Error parsing TLS response: " + e.getMessage());
        }
    }
}
