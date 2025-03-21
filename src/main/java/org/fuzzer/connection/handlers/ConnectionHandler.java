package org.fuzzer.connection.handlers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ConnectionHandler {
    private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    private TCPConnectionHandler tcpConnectionHandler = new TCPConnectionHandler();

    public ConnectionHandler() throws IOException {}

    public void sendData(byte[] data) throws IOException {
        tcpConnectionHandler.sendData(data);
        receiveData();
    }

    private void receiveData() throws IOException {
        this.outputStream.write(tcpConnectionHandler.getServerResponse());
    }

    public byte[] fetchData(){
        byte[] dataToFetch = outputStream.toByteArray();
        outputStream.reset();
        return dataToFetch;
    }
}
