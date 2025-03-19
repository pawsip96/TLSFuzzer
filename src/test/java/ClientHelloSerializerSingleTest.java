
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ClientHelloSerializerSingleTest {

    @Test
    public void testSerializeClientHelloMessage() {
        // Step 1: Create a ClientHelloMessage and set its fields
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage();
        clientHelloMessage.setProtocolVersion(new byte[]{0x03, 0x03}); // TLS 1.2

        // Step 2: Create the ClientHelloSerializer
        ClientHelloSerializer serializer = new ClientHelloSerializer(clientHelloMessage, null);

        // Step 3: Serialize the ClientHelloMessage
        byte[] serializedMessage = serializer.serialize();

        // Step 4: Define the expected output
        byte[] expectedOutput = new byte[]{
                0x03, 0x03, // Protocol version (TLS 1.2)
                0x00, 0x00, 0x00, 0x00, // Unix time (not used in TLS 1.2)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (28 bytes, all zeros)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // Session ID length (0)
                // No session ID bytes
                0x00, 0x02, // Cipher suite length (2 bytes)
                0x00, 0x2F, // Cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
                0x01, // Compression length (1 byte)
                0x00, // Compression method (null compression)
                0x00, 0x00 // Extensions length (0 bytes)
                // No extension bytes
        };

        // Step 5: Verify the serialized output matches the expected output
        assertArrayEquals(expectedOutput, serializedMessage, "Serialized ClientHelloMessage does not match expected output");
    }
}