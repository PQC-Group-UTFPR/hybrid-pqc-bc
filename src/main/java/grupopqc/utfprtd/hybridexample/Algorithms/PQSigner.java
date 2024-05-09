package grupopqc.utfprtd.hybridexample.Algorithms;

import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;

/*

 * based on //https://github.com/bcgit/bc-java/blob/4a10c27a03bddd96cf0a3663564d0851425b27b9/core/src/test/java/org/bouncycastle/pqc/crypto/test/CrystalsDilithiumTest.java#L248
*/
public class PQSigner implements SignerStrategy {

    private AsymmetricCipherKeyPair PQkeyPair;
    private SecureRandom random;
    
    @Override
    public void init(String pqAlgorithm) {
        
        random = new SecureRandom();
        
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        switch (pqAlgorithm){
            case "Dilithium2":
                keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium2));
                break;
            case "Dilithium3":
                keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium3));
                break;
            case "Dilithium5":
                keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium5));
                break;
            default:
                keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium3));
        }
        PQkeyPair = keyGen.generateKeyPair();
    }

    @Override
    public byte[] sign(byte[] message) {
                    
        DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)PQkeyPair.getPrivate();                
        MessageSigner ms = new DilithiumSigner();
        ms.init(true, new ParametersWithRandom(skparam, random));
        
        byte[] s = ms.generateSignature(message);
        return s;
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        DilithiumSigner ms = new DilithiumSigner();
        DilithiumPublicKeyParameters pkparam = (DilithiumPublicKeyParameters)PQkeyPair.getPublic();
        ms.init(false, pkparam);
                
        return ms.verifySignature(message, signature);
    }
}