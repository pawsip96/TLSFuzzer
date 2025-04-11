package org.fuzzer.message.parsers;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;

import java.util.ArrayList;
import java.util.List;

public class ServerHelloExtensionsParser {

    private final byte[] extensionBytes;
    private final List<ExtensionMessage> extensions;

    public ServerHelloExtensionsParser(byte[] extensionBytes) {
        this.extensionBytes = extensionBytes;
        this.extensions = new ArrayList<>();
    }

    public List<ExtensionMessage> parse() {
        if (extensionBytes == null || extensionBytes.length == 0) {
            return extensions;
        }

        int pointer = 0;
        while (pointer < extensionBytes.length) {
            // Each extension has at least 4 bytes (2 bytes type + 2 bytes length)
            if (pointer + 4 > extensionBytes.length) {
                throw new IllegalArgumentException("Malformed extension data");
            }

            // Parse extension type (2 bytes)
            byte[] typeBytes = new byte[]{extensionBytes[pointer], extensionBytes[pointer + 1]};
            ExtensionType type = ExtensionType.getExtensionType(typeBytes);
            pointer += 2;

            // Parse extension length (2 bytes)
            int length = ArrayConverter.bytesToInt(
                    new byte[]{0, 0, extensionBytes[pointer], extensionBytes[pointer + 1]}
            );
            pointer += 2;

            // Check if we have enough data for the extension
            if (pointer + length > extensionBytes.length) {
                throw new IllegalArgumentException("Extension length exceeds available data");
            }

            // Get extension data
            byte[] extensionData = new byte[length];
            System.arraycopy(extensionBytes, pointer, extensionData, 0, length);
            pointer += length;

            // Create appropriate extension message based on type
            ExtensionMessage extension = createExtension(type, extensionData);
            if (extension != null) {
                extensions.add(extension);
            }
        }

        return extensions;
    }

    private ExtensionMessage createExtension(ExtensionType type, byte[] extensionData) {
        switch (type) {
            case KEY_SHARE:
                return parseKeyShareExtension(extensionData);
            case SERVER_NAME_INDICATION:
                return parseServerNameIndicationExtension(extensionData);
            case SUPPORTED_VERSIONS:
                return parseSupportedVersionsExtension(extensionData);
            // Add more extension types as needed
            default:
//                // For unknown extensions, create a generic extension message
//                ExtensionMessage generic = new ExtensionMessage();
//                generic.setExtensionType(type);
//                generic.setExtensionBytes(extensionData);
                return null;
        }
    }

    private ExtensionMessage parseKeyShareExtension(byte[] extensionData) {
        KeyShareExtensionMessage extension = new KeyShareExtensionMessage();
        extension.setExtensionType(ExtensionType.KEY_SHARE.getValue());
        extension.setExtensionBytes(extensionData);

        int pointer = 0;

        // Parse KeyShareList length (2 bytes)
        if (extensionData.length >= 2) {
            byte[] keyShareListLength = new byte[]{0, 0, extensionData[pointer], extensionData[pointer+1]};
            extension.setExtensionType(keyShareListLength);
            pointer += 2;


            // Save the position where the key share list bytes start
            int keyShareListStart = pointer;

            // Parse individual KeyShareEntries
            while (pointer < extensionData.length) {
                // Each KeyShareEntry has: 2 bytes group + 2 bytes length + N bytes key
                if (pointer + 4 > extensionData.length) {
                    break; // Not enough data for another entry
                }

                // Parse key length (2 bytes) - CORRECT VERSION
                int keyLength = ((extensionData[pointer] & 0xFF) << 8) | (extensionData[pointer+1] & 0xFF);
                pointer += 2;

                // Parse key exchange data
                if (pointer + keyLength > extensionData.length) {
                    break; // Not enough data for the key
                }

                byte[] keyExchange = new byte[keyLength];
                System.arraycopy(extensionData, pointer, keyExchange, 0, keyLength);
                pointer += keyLength;

                // Create and add KeyShareEntry
                KeyShareEntry entry = new KeyShareEntry();
                entry.setPublicKey(keyExchange);
                entry.setPublicKeyLength(keyLength);
                extension.getKeyShareList().add(entry);
            }

            // Set the complete keyShareListBytes
            byte[] keyShareListBytes = new byte[pointer - keyShareListStart];
            System.arraycopy(extensionData, keyShareListStart, keyShareListBytes, 0, keyShareListBytes.length);
            extension.setKeyShareListBytes(keyShareListBytes);
        }

        // Check for retry request mode (TLS 1.3 special case)
        if (extensionData.length == 2 && (extension.getKeyShareListLength() != null && extension.getKeyShareListLength().getValue() == 0)) {
            extension.setRetryRequestMode(true);
        }


        return extension;
    }

    private ExtensionMessage parseServerNameIndicationExtension(byte[] extensionData) {
        ServerNameIndicationExtensionMessage extension = new ServerNameIndicationExtensionMessage();
        extension.setExtensionType(ExtensionType.SERVER_NAME_INDICATION.getValue());
        extension.setExtensionBytes(extensionData);

        // Parse server name list (implementation depends on your needs)
        // ...

        return extension;
    }

    private ExtensionMessage parseSupportedVersionsExtension(byte[] extensionData) {
        SupportedVersionsExtensionMessage extension = new SupportedVersionsExtensionMessage();
        extension.setExtensionType(ExtensionType.SUPPORTED_VERSIONS.getValue());
        extension.setExtensionBytes(extensionData);

        // Parse supported versions (implementation depends on your needs)
        // ...

        return extension;
    }
}