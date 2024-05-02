package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.RSA;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

import java.lang.reflect.Array;
import java.util.ArrayList;

public class HybridPQSigner implements SignerStrategy {

    @Override
    public ArrayList<MessageSigner> init(boolean keyUsageForSigning1, boolean keyUsageForSigning2, ArrayList<CipherParameters> parameters) {//testar hashmap

        MessageSigner ms1 = new DilithiumSigner();
        MessageSigner ms2 = RSA.generateKeyPair();

        ms1.init(keyUsageForSigning1, parameters.get(0));
        ms2.init(keyUsageForSigning2, parameters.get(1));

        ArrayList<MessageSigner> signedMessages = new ArrayList<>();
        signedMessages.add(ms1);
        signedMessages.add(ms2);

        return signedMessages;

    }

    @Override
    public byte[] sign(MessageSigner ms, byte[] message) {
        byte[] s = ms.generateSignature(message);
        return s;
    }

    @Override
    public boolean verify(MessageSigner ms, byte[] message, byte[] signature) {
        return ms.verifySignature(message, signature);
    }
}