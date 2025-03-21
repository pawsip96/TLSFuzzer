package org.fuzzer.connection;

import java.io.*;
import java.net.*;

public class TCPConnection {

    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;

    public TCPConnection(String serverAddress, int port) throws IOException {
        // Create and establish the socket connection to the server
        socket = new Socket(serverAddress, port);
        outputStream = socket.getOutputStream();
        inputStream = socket.getInputStream();
    }

    // Method to send raw data to the server
    public void sendRawData(byte[] data) throws IOException {
        outputStream.write(data);
        outputStream.flush();
    }

    // Method to receive raw data from the server
    public byte[] receiveRawData() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byteArrayOutputStream.write(buffer, 0, bytesRead);
        }

        return byteArrayOutputStream.toByteArray();
    }

    // Close the socket connection
    public void close() throws IOException {
        inputStream.close();
        outputStream.close();
        socket.close();
    }
}
