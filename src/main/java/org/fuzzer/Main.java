package org.fuzzer;

import org.fuzzer.executor.ClientHelloExecutor;
import org.fuzzer.executor.TestExecutor;
import org.fuzzer.message.peparators.ClientHelloMessage;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage();

        TestExecutor testExecutor = new TestExecutor(clientHelloMessage);
        testExecutor.executeTest();

    }

}
