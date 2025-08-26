package org.fuzzer.testExecution;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import org.fuzzer.executor.ClientHelloExecutor;
import org.fuzzer.message.parsers.TLSHeaderParser;
import org.fuzzer.message.peparators.ClientHelloMessage;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClientHelloTests {

    @Test
    public void validClientHello(){
        ClientHelloExecutor testExecutor = new ClientHelloExecutor(new ClientHelloMessage());
        testExecutor.executeTest();

        TLSHeaderParser tlsHeader = testExecutor.getTlsHeaderParser();
        HandshakeMessageType messageType = tlsHeader.getHandshakeMessageType();
        System.out.println(messageType.toString());
        assertEquals("SERVER_HELLO", messageType.toString());

    }
}
