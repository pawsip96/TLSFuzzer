package org.fuzzer.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileWriter;
import java.io.IOException;

public class KeyLogWriter {

    private static final Logger LOGGER = LogManager.getLogger(KeyLogWriter.class);
    private static final String CLIENT_RANDOM_PREFIX = "CLIENT_RANDOM ";
    private static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET_PREFIX = "CLIENT_HANDSHAKE_TRAFFIC_SECRET ";
    private static final String SERVER_HANDSHAKE_TRAFFIC_SECRET_PREFIX = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
    private static final String CLIENT_TRAFFIC_SECRET_0_PREFIX = "CLIENT_TRAFFIC_SECRET_0 ";
    private static final String SERVER_TRAFFIC_SECRET_0_PREFIX = "SERVER_TRAFFIC_SECRET_0 ";

    private final String keyLogFilePath;
    private final TlsContext tlsContext;

    public KeyLogWriter(TlsContext tlsContext, String keyLogFilePath) {
        this.tlsContext = tlsContext;
        this.keyLogFilePath = keyLogFilePath;
    }

    /**
     * Logs TLS 1.3 handshake secrets for Wireshark decryption
     */
    public void logTls13HandshakeSecrets() {
        if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            LOGGER.debug("Not TLS 1.3, skipping Wireshark key logging");
            return;
        }

        try (FileWriter writer = new FileWriter(keyLogFilePath, true)) {
            byte[] clientRandom = tlsContext.getClientRandom();
            byte[] clientHandshakeTrafficSecret = tlsContext.getClientHandshakeTrafficSecret();
            byte[] serverHandshakeTrafficSecret = tlsContext.getServerHandshakeTrafficSecret();

            if (clientRandom != null && clientHandshakeTrafficSecret != null) {
                String clientRandomHex = ArrayConverter.bytesToHexString(clientRandom);
                String clientHandshakeSecretHex = ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret);

                writer.write(CLIENT_RANDOM_PREFIX + clientRandomHex + " " + clientHandshakeSecretHex + "\n");
                writer.write(CLIENT_HANDSHAKE_TRAFFIC_SECRET_PREFIX + clientRandomHex + " " + clientHandshakeSecretHex + "\n");
                LOGGER.debug("Logged CLIENT_HANDSHAKE_TRAFFIC_SECRET to keys.log");
            }

            if (clientRandom != null && serverHandshakeTrafficSecret != null) {
                String clientRandomHex = ArrayConverter.bytesToHexString(clientRandom);
                String serverHandshakeSecretHex = ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret);

                writer.write(SERVER_HANDSHAKE_TRAFFIC_SECRET_PREFIX + clientRandomHex + " " + serverHandshakeSecretHex + "\n");
                LOGGER.debug("Logged SERVER_HANDSHAKE_TRAFFIC_SECRET to keys.log");
            }

            writer.flush();
        } catch (IOException e) {
            LOGGER.error("Failed to write to keys.log file", e);
        }
    }

    /**
     * Logs TLS 1.3 application traffic secrets for Wireshark decryption
     * This should be called after the handshake is complete and application keys are derived
     */
    public void logTls13ApplicationSecrets() {
        if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            return;
        }

        try {
            HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser().getSelectedCipherSuite());
            DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
                    ProtocolVersion.TLS13, tlsContext.getChooser().getSelectedCipherSuite());

            byte[] handshakeSecret = tlsContext.getHandshakeSecret();
            byte[] masterSecret = tlsContext.getMasterSecret();
            byte[] clientRandom = tlsContext.getClientRandom();
            byte[] handshakeDigest = tlsContext.getDigest().getRawBytes();

            if (handshakeSecret != null && clientRandom != null) {
                // Derive client application traffic secret
                byte[] clientTrafficSecret = HKDFunction.deriveSecret(
                        hkdfAlgorithm, digestAlgo.getJavaName(), masterSecret,
                        "c ap traffic", handshakeDigest);

                // Derive server application traffic secret
                byte[] serverTrafficSecret = HKDFunction.deriveSecret(
                        hkdfAlgorithm, digestAlgo.getJavaName(), masterSecret,
                        "s ap traffic", handshakeDigest);

                try (FileWriter writer = new FileWriter(keyLogFilePath, true)) {
                    String clientRandomHex = ArrayConverter.bytesToHexString(clientRandom);
                    String clientTrafficSecretHex = ArrayConverter.bytesToHexString(clientTrafficSecret);
                    String serverTrafficSecretHex = ArrayConverter.bytesToHexString(serverTrafficSecret);

                    writer.write(CLIENT_TRAFFIC_SECRET_0_PREFIX + clientRandomHex + " " + clientTrafficSecretHex + "\n");
                    writer.write(SERVER_TRAFFIC_SECRET_0_PREFIX + clientRandomHex + " " + serverTrafficSecretHex + "\n");

                    LOGGER.debug("Logged application traffic secrets to keys.log");
                }
            }
        } catch (IOException | CryptoException e) {
            LOGGER.error("Failed to derive or log application secrets", e);
        }
    }

    /**
     * Utility method to convert bytes to hex string (compatible with Wireshark format)
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Call this method from ServerHelloHandler after handshake secrets are set
     */
    public static void logHandshakeSecretsFromHandler(TlsContext tlsContext, String keyLogFilePath) {
        KeyLogWriter keyLogger = new KeyLogWriter(tlsContext, keyLogFilePath);
        keyLogger.logTls13HandshakeSecrets();
    }

    /**
     * Call this method after the handshake is complete to log application secrets
     */
    public static void logApplicationSecrets(TlsContext tlsContext, String keyLogFilePath) {
        KeyLogWriter keyLogger = new KeyLogWriter(tlsContext, keyLogFilePath);
        keyLogger.logTls13ApplicationSecrets();
    }
}