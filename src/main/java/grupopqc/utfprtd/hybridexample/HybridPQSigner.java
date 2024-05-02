package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.RSA;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

import java.lang.reflect.Array;
import java.util.ArrayList;

public class HybridPQSigner implements SignerStrategy {

    private KeyPair classicKeyPair;
    
    @Override
    public MessageSigner init(boolean keyUsageForSigning1, CipherParameters parameters) {//testar hashmap
        classicKeyPair = RSA.generateKeyPair();
        RSA.setPrivateKey(classicKeyPair.getPrivate());
        RSA.setPublicKey(classicKeyPair.getPublic());
        MessageSigner ms1 = new DilithiumSigner();        
        ms1.init(keyUsageForSigning1,parameters);        
        return ms1;
    }
    
    

    /*
    * TODO: check https://www.overleaf.com/read/vnczxhctwxkv#2e8e14 slide 13    
    */
    @Override
    public byte[] sign(MessageSigner ms, byte[] message) {
        byte[] s = ms.generateSignature(message);
        byte[] s2 = RSA.sign(message);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(s);
        outputStream.write(s2);

        byte ret[] = outputStream.toByteArray();
        return ret;
    }

    @Override
    public boolean verify(MessageSigner ms, byte[] message, byte[] signature) {
        
        Arrays.copyOfRange(input, blockStart, i);
        
        
        return ms.verifySignature(message, signature);
    }
}