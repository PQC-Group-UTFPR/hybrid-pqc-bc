package grupopqc.utfprtd.hybridexample;

import static grupopqc.utfprtd.hybridexample.Hybridexample.PublicKeyReceiver;
import static grupopqc.utfprtd.hybridexample.Hybridexample.ukm;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

/**
 * 
 */
public class KEM implements KeyEstablishmentStrategy {

    private KyberParameterSpec[] kyberParameterSpecs = {
                KyberParameterSpec.kyber512,
                KyberParameterSpec.kyber768,
                KyberParameterSpec.kyber1024
        };
    
    @Override
    public Map<String, KeyPair> keyGeneration(String algorithmSpec, String providerName) {
        Map<String, KeyPair> r = new HashMap<>();
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithmSpec, providerName);
            //TODO: function to search and map algorithm name to ParameterSpec Object
            KyberParameterSpec kyberParameterSpec = kyberParameterSpecs[1];            
            kpg.initialize(kyberParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
                        
            r.put("KEM", kp);                                   
            return r;
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            //TODO: Logger?
            return r;
        }
    }

    @Override
    public Map<String, byte[]> encapsulation(String algorithmSpec, String providerName, String encAlgoName, Map<String, KeyPair> keys) {
        KeyGenerator keyGen;
        Map<String, byte[]> r = new HashMap<>();
        try {            
            keyGen = KeyGenerator.getInstance(algorithmSpec, providerName);            
            PublicKey recipientPublicKey = keys.get("OtherParty-KEM").getPublic();
            
            //KEMGenerate Spec
            keyGen.init(new KEMGenerateSpec((PublicKey) recipientPublicKey, encAlgoName), new SecureRandom());            
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
                                    
            //KEM encaps
            byte[] encapsulatedKey = secEnc1.getEncapsulation();
            //get K from PQC KEM
            byte[] K = secEnc1.getEncoded();
             
            r.put("C", encapsulatedKey); 
            r.put("K", K);
            
            return r;                 
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {        
            return r;
        }
    }

    @Override
    public byte[] decapsulation(String algorithmSpec, String providerName, String encAlgoName, byte[] C, Map<String, KeyPair> keys) {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance(algorithmSpec, providerName);
            //KEMExtract spec
            keyGen.init(new KEMExtractSpec((PrivateKey) keys.get("KEM").getPrivate(), C, encAlgoName), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            
            //KEM Decaps
            byte[] K = secEnc2.getEncoded();                                                       
            
            return K; 
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {        
            return null;
        } 
    }
    
}
