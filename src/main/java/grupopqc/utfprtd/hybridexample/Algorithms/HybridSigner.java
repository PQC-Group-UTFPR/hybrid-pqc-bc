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
    
    
    @Override
    public void init(String pqAlgorithm) {
        
        random = new SecureRandom();
        
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        try {
            switch (pqAlgorithm) {
                case "Dilithium2":
                    keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium2));
                    hIngredient = RSA.generateKeyPair(3072);//get keysize from config or env file
                    break;

                case "Dilithium3":
                    keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium3));
                    hIngredient = RSA.generateKeyPair(7680);
                    break;
                case "Dilithium5":
                    keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium5));
                    hIngredient = RSA.generateKeyPair(15360);
                    break;
                default:
                    keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3));
                    hIngredient = RSA.generateKeyPair(7680);//get keysize from config or env file
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
        try {
            //signing using RSA
            String rsaSignature = RSA.sign(new String(message, "UTF-8"));
            return (new String(s, "UTF-8") + rsaSignature).getBytes("UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, String dilithiumLevel) {
        try {
            byte[] dilithiumSignature = null;
            byte[] rsaSignature = null;

            switch (dilithiumLevel) {
                case "Dilithium2":
                    dilithiumSignature = new byte[2528];
                    rsaSignature = new byte[3072];
                    System.arraycopy(signature, 0, dilithiumSignature, 0, 2528);
                    System.arraycopy(signature, 0, rsaSignature, 0, 3072);
                case "Dilithium3":
                    dilithiumSignature = new byte[4000];
                    rsaSignature = new byte[7680];
                    System.arraycopy(signature, 0, dilithiumSignature, 0, 4000);
                    System.arraycopy(signature, 0, rsaSignature, 0, 7680);
                case "Dilithium5":
                    dilithiumSignature = new byte[4864];
                    rsaSignature = new byte[15360];
                    System.arraycopy(signature, 0, dilithiumSignature, 0, 4864);
                    System.arraycopy(signature, 0, rsaSignature, 0, 15360);
            }

            DilithiumSigner ms = new DilithiumSigner();
            DilithiumPublicKeyParameters pkparam = (DilithiumPublicKeyParameters) PQkeyPair.getPublic();
            ms.init(false, pkparam);

            boolean dilithiumResult = ms.verifySignature(message, dilithiumSignature);

            boolean rsaResult = RSA.verify(new String(rsaSignature, "UTF-8"), new String(message, "UTF-8"));

            return dilithiumResult && rsaResult;
        }catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
