package grupopqc.utfprtd.hybridexample.Algorithms;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

/**
 *
 * This hybrid signer follows PQSigner and adds by default: 
 * RSA3072 with Dilithium2 
 * RSA7680 with Dilithium3
 * RSA15360 with Dilithium5
 * P256-ECDSA with Dilithium2 //TODO 
 * P384-ECDSA with Dilithium3 //TODO
 * P521-ECDSA with Dilithium5 //TODO
 * 
 * Note that for RSA we follow http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf 
 * so RSA 2048 (112 bits security) is not currently used.
 */
public class HybridSigner implements SignerStrategy {

    private KeyPair hIngredient;
    private AsymmetricCipherKeyPair PQkeyPair;
    private SecureRandom random;
    private int pqSignatureSize;
    private int cSignatureSize;
    
    
    @Override
    public void init(String pqAlgorithm) {
        
        random = new SecureRandom();
        
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        try {
            switch (pqAlgorithm) {
                case "Dilithium2":
                    keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium2));
                    hIngredient = RSA.generateKeyPair(3072);//get keysize from config or env file
                    pqSignatureSize = 2420;
                    cSignatureSize = RSA.getKeySize() /8 ; //should be the same size...
                    break;

                case "Dilithium3":
                    keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium3));
                    hIngredient = RSA.generateKeyPair(7680);
                    pqSignatureSize = 3293;
                    cSignatureSize = RSA.getKeySize() / 8;
                    break;
                case "Dilithium5":
                    keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium5));
                    hIngredient = RSA.generateKeyPair(15360);
                    pqSignatureSize = 4595;
                    cSignatureSize = RSA.getKeySize() / 8;
                    break;
                default:
                    keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3));
                    hIngredient = RSA.generateKeyPair(7680);//get keysize from config or env file
                    pqSignatureSize = 3293;
                    cSignatureSize = RSA.getKeySize() / 8;
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HybridSigner.class.getName()).log(Level.SEVERE, null, ex);
        }

        PQkeyPair = keyGen.generateKeyPair();
    }

    @Override
    public byte[] sign(byte[] message) {
                    
        DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)PQkeyPair.getPrivate();                
        MessageSigner ms = new DilithiumSigner();
        ms.init(true, new ParametersWithRandom(skparam, random));
        
        byte[] s = ms.generateSignature(message);
        byte[] concatSignature = new byte[pqSignatureSize+cSignatureSize];
        try {
            //signing using RSA
            byte[] rsaSignature = RSA.sign(new String(message, "UTF-8"));
            //return (new String(s, "UTF-8") + rsaSignature).getBytes("UTF-8");
            System.arraycopy(s, 0, concatSignature, 0, pqSignatureSize);
            System.arraycopy(rsaSignature, 0, concatSignature, pqSignatureSize, cSignatureSize);
            return concatSignature;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        try {
            byte[] dilithiumSignature = null;
            byte[] rsaSignature = null;

            dilithiumSignature = new byte[pqSignatureSize];
            rsaSignature = new byte[cSignatureSize];
            System.arraycopy(signature, 0, dilithiumSignature, 0, pqSignatureSize);
            System.arraycopy(signature, pqSignatureSize, rsaSignature,0 , cSignatureSize);
            

            DilithiumSigner ms = new DilithiumSigner();
            DilithiumPublicKeyParameters pkparam = (DilithiumPublicKeyParameters) PQkeyPair.getPublic();
            ms.init(false, pkparam);

            boolean dilithiumResult = ms.verifySignature(message, dilithiumSignature);

            
            
            boolean rsaResult = RSA.verify(rsaSignature, new String(message, "UTF-8"));           
            
            return dilithiumResult && rsaResult;
        }catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}