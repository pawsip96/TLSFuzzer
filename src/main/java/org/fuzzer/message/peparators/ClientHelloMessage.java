package org.fuzzer.message.peparators;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ClientHelloMessage extends de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage {

    private final TlsContext tlsContext;

    public ClientHelloMessage() {
        super();  // Call parent constructor
        Config config = Config.createConfig();
        this.tlsContext = new TlsContext(config);
        this.addExtension(new SupportedVersionsExtensionMessage());
        this.addExtension(new SignatureAndHashAlgorithmsExtensionMessage());
        this.addExtension(new KeyShareExtensionMessage(config));
        this.addExtension(new EllipticCurvesExtensionMessage());
        prepareMessage();
    }

    private void prepareMessage() {
        ClientHelloHandler clientHelloHandler = this.getHandler(tlsContext);
        ClientHelloPreparator clientHelloPreparator = clientHelloHandler.getPreparator(this);
        clientHelloPreparator.prepareHandshakeMessageContents();
        clientHelloPreparator.prepare();
        clientHelloPreparator.afterPrepare();
    }
}
