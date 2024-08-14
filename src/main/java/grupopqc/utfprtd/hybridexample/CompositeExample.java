package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.Algorithms.RSA;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Primitive;
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
import org.bouncycastle.util.encoders.Base64;

/**
 *
 *
 */
public class CompositeExample {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        SecureRandom random = new SecureRandom();

        //GENERATE KEYS for the subject: ckeypair and pqAsymmetricKeyPair
        KeyPair ckeyPair = RSA.generateKeyPair(2048);
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        keyGen.init(new DilithiumKeyGenerationParameters(random,DilithiumParameters.dilithium3));
        AsymmetricCipherKeyPair pqAsymmetricKeyPair = keyGen.generateKeyPair();
        
        //convert asymmetric key pair to key pair
        DilithiumPublicKeyParameters pkParam = (DilithiumPublicKeyParameters) pqAsymmetricKeyPair.getPublic();                
        DilithiumPrivateKeyParameters skParam = (DilithiumPrivateKeyParameters) pqAsymmetricKeyPair.getPrivate();
        KeyPair pqKeyPair = new KeyPair(new BCDilithiumPublicKey(pkParam), new BCDilithiumPrivateKey(skParam));
        
        //Create a composite private key: PQ first        
        CompositePrivateKey compositePrivKey = new CompositePrivateKey( pqKeyPair.getPrivate(), ckeyPair.getPrivate());
        
        //create a composite public key Dilithium3-RSA2048 (well, just following the link below... check HybridSigner.java for different hybrid mappings)
        CompositePublicKey compositePubKey = new CompositePublicKey(pqKeyPair.getPublic(), ckeyPair.getPublic());
        
        //test: print composite PK, you can match this with https://github.com/EntrustCorporation/draft-ounsworth-pq-composite-keys/blob/master/sampledata/current/id-Dilithium3-RSA_pub.pem and https://lapo.it/asn1js/        
        byte[] encodedBytes = Base64.encode(ASN1Primitive.fromByteArray(compositePubKey.getEncoded()).getEncoded());
        System.out.println("Pk-composite encoded:" + new String(encodedBytes));

        encodedBytes = Base64.encode(ASN1Primitive.fromByteArray(compositePrivKey.getEncoded()).getEncoded());
        System.out.println("\nComp. Private Key encoded:" + new String(encodedBytes));
        
        
        //TODO: Create a x509 composite certificate example.
    }

}
