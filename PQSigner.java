package grupopqc.utfprtd.hybridexample;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

import javax.crypto.Cipher;
import java.util.ArrayList;


public class PQSigner implements SignerStrategy {

    @Override
    public ArrayList<MessageSigner> init(boolean keyUsageForSigning1, boolean keyUsageForSigning2, ArrayList<CipherParameters> parameters) {
        //dilithium2
        ArrayList<MessageSigner> signers = new ArrayList<>();

        MessageSigner ms = new DilithiumSigner();
        ms.init(keyUsageForSigning1, parameters.get(0));

        signers.add(ms);
        return signers;
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