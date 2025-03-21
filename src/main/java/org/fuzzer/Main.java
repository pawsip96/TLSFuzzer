package org.fuzzer;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.fuzzer.connection.TCPConnection;

import java.io.IOException;

import static org.fuzzer.message.serializers.MessageSerializer.*;

public class Main {

    public static void main(String[] args) throws IOException {
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage();
        clientHelloMessage.setProtocolVersion(ProtocolVersion.TLS13.getValue());

        Config config = Config.createConfig();
        TlsContext tlsContext = new TlsContext(config);

        ClientHelloHandler clientHelloHandler = clientHelloMessage.getHandler(tlsContext);
        ClientHelloPreparator clientHelloPreparator = clientHelloHandler.getPreparator(clientHelloMessage);
        clientHelloPreparator.prepareHandshakeMessageContents();
        clientHelloPreparator.prepare();
        clientHelloPreparator.afterPrepare();
        ClientHelloSerializer clientHelloSerializer = new ClientHelloSerializer(clientHelloMessage, ProtocolVersion.TLS13);

        byte[] rawMessage = clientHelloSerializer.serialize();

        TCPConnection tcpConnection = new TCPConnection("localhost", 4433);

        tcpConnection.sendRawData(serializeMessage(rawMessage, ProtocolVersion.TLS13));
        System.out.println("Sent ClientHello message to server.");

        // Step 5: Receive the server's response (if any)
        byte[] serverResponse = tcpConnection.receiveRawData();
        System.out.println("Received response from server: " + new String(serverResponse));

        // Step 6: Close the connection
        tcpConnection.close();
        System.out.println("Connection closed.");
    }

}
