package x509;

import grupopqc.utfprtd.hybridexample.Algorithms.RSA;
import java.security.KeyPair;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;

/**
 *
 * 
 */
public class CompositeExample {
    
    public static void main(String[] args) throws Exception{

        SecureRandom random = new SecureRandom();

        //GENERATE KEYS: ckeypair and pqAsymmetricKeyPair
        KeyPair ckeyPair = RSA.generateKeyPair(3072);
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium2));
        AsymmetricCipherKeyPair pqAsymmetricKeyPair = keyGen.generateKeyPair();
        
        //convert asymmetric key pair to key pair
        DilithiumPublicKeyParameters pkParam = (DilithiumPublicKeyParameters) pqAsymmetricKeyPair.getPublic();                
        DilithiumPrivateKeyParameters skParam = (DilithiumPrivateKeyParameters) pqAsymmetricKeyPair.getPrivate();
        KeyPair pqKeyPair = new KeyPair(new BCDilithiumPublicKey(pkParam), new BCDilithiumPrivateKey(skParam));
        
        
        //Create a composite private key        
        CompositePrivateKey compositePrivKey = new CompositePrivateKey(ckeyPair.getPrivate(), pqKeyPair.getPrivate());
                        
        //create a composite public key RSA3072-Dilithium2
        CompositePublicKey compositePubKey = new CompositePublicKey(ckeyPair.getPublic(), pqKeyPair.getPublic());
        
        //test: save composite PK
        System.out.println("PK:" + compositePubKey.getAlgorithm());
        System.out.println("PK format:" + compositePubKey.getFormat());
        //System.out.println(new String(compositePubKey.getEncoded()));
        System.out.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(compositePubKey.getEncoded())));
        
        //TODO create a composite signature
        
        //TODO: Create a x509 composite certificate example.
    }
}
