package org.fuzzer;

import org.fuzzer.executor.ClientHelloExecutor;
import org.fuzzer.message.peparators.ClientHelloMessage;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage();

        ClientHelloExecutor clientHelloExecutor = new ClientHelloExecutor(clientHelloMessage);
        clientHelloExecutor.executeMessage();

    }

}
