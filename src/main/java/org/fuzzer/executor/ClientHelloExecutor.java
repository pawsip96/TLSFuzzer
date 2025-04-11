package org.fuzzer.executor;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import org.fuzzer.connection.handlers.ConnectionHandler;
import org.fuzzer.message.peparators.ClientHelloMessage;
import org.fuzzer.message.serializers.MessageSerializer;

import java.io.IOException;

public class ClientHelloExecutor {

    private byte[] data;
    public byte[] response;
    private ConnectionHandler connectionHandler = new ConnectionHandler();

    public ClientHelloExecutor(ClientHelloMessage clientHelloMessage) throws IOException {
        ClientHelloSerializer clientHelloSerializer = new ClientHelloSerializer(
                clientHelloMessage, ProtocolVersion.TLS13);

        this.data = clientHelloSerializer.serialize();
    }

    public void executeMessage() throws IOException {
        data = MessageSerializer.serializeMessage(data);
        connectionHandler.sendData(data);
        response = connectionHandler.fetchData();
    }

    public byte[] getResponse() {
        return response;
    }
}
