package org.fuzzer.connection.handlers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.fuzzer.connection.TCPConnection;

import java.io.IOException;

public class TCPConnectionHandler {

    private final TCPConnection tcpConnection;

    private static final Logger LOGGER = LogManager.getLogger();


    public TCPConnectionHandler() throws IOException {
        this.tcpConnection = new TCPConnection("localhost", 4433);
    }

    public void sendData(byte[] data) throws IOException {
        tcpConnection.sendRawData(data);
        LOGGER.debug("Data send: {}", byteToHex(data));
    }

    public byte[] getServerResponse() throws IOException {
        byte[] serverResponse = tcpConnection.receiveRawData();
        LOGGER.debug("Received Data from the server: {}", byteToHex(serverResponse));
        return serverResponse;
    }

    private String byteToHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }


}
