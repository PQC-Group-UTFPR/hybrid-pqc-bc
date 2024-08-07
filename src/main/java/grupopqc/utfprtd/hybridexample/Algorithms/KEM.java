package grupopqc.utfprtd.hybridexample.Algorithms;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

/**
 * 
 */
public class KEM implements KeyEstablishmentStrategy {

    private static final Logger LOGGER = Logger.getLogger(HybridKEMECDH.class.getName());
    private KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber768;
    private String pqcParameterSpecs;
    private String providerName = "BCPQC";

    

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    @Override
    public Map<String, KeyPair> keyGeneration() {
        Map<String, KeyPair> keyPairMap = new HashMap<>();
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            KyberParameterSpec kyberParameterSpec = this.kyberParameterSpec;
            keyPairGenerator.initialize(kyberParameterSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
                        
            keyPairMap.put("KEM", keyPair);
            return keyPairMap;
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            LOGGER.log(Level.SEVERE, e.toString());
            return keyPairMap;
        }
    }

    @Override
    public Map<String, byte[]> encapsulation(String encAlgoName, Map<String, KeyPair> keys) {
        KeyGenerator keyGenerator;
        Map<String, byte[]> kemGeneratedMap = new HashMap<>();
        try {            
            keyGenerator = KeyGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            PublicKey recipientPublicKey = keys.get("OtherParty-KEM").getPublic();
            
            //KEMGenerate Spec
            keyGenerator.init(new KEMGenerateSpec((PublicKey) recipientPublicKey, encAlgoName), new SecureRandom());
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
                                    
            //KEM encaps
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            //get K from PQC KEM
            byte[] keyWithEncapsulationEncoded = secretKeyWithEncapsulation.getEncoded();
             
            kemGeneratedMap.put("C", encapsulatedKey);
            kemGeneratedMap.put("K", keyWithEncapsulationEncoded);
            
            return kemGeneratedMap;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException err) {
            LOGGER.log(Level.SEVERE, err.toString());
            System.out.println("The fail is here:"+this.pqcParameterSpecs + " and kyber:"+this.kyberParameterSpec.getName());
            return kemGeneratedMap;
        }
    }

    @Override
    public byte[] decapsulation(String encAlgoName, byte[] C, Map<String, KeyPair> keys) {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            //KEMExtract spec
            keyGenerator.init(new KEMExtractSpec((PrivateKey) keys.get("KEM").getPrivate(), C, encAlgoName), new SecureRandom());
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
            
            //KEM Decaps
            return secretKeyWithEncapsulation.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException err) {
            LOGGER.log(Level.SEVERE, err.toString());
            return null;
        } 
    }

    public void setPqcParameterSpecs(String algorithm){
        this.pqcParameterSpecs = algorithm;
        if (Objects.equals(algorithm, "KYBER512")){
            this.kyberParameterSpec = KyberParameterSpec.kyber512;
        }
        if (Objects.equals(algorithm, "KYBER768")){
            this.kyberParameterSpec = KyberParameterSpec.kyber768;
        }
        if (Objects.equals(algorithm, "KYBER1024")){
            this.kyberParameterSpec = KyberParameterSpec.kyber1024;
        }
    }
    
    //IDs are to match the number of a test
    //Component algo should not be here; because
    //This is actually just for the speed test class.
    //The setPqcParameterSpecs() method should be used instead
    @Override
    public void setPqcIDParameterSpecs(String algorithm, String componentAlgo, int ID) {
        if (algorithm.contains("KYBER")) {       
            if (ID == 0) {
                this.kyberParameterSpec = KyberParameterSpec.kyber512;
                this.pqcParameterSpecs = "KYBER512";
            }
            if (ID == 1){
                this.kyberParameterSpec = KyberParameterSpec.kyber768;
                this.pqcParameterSpecs = "KYBER768";
            }
            if (ID == 2){
                this.kyberParameterSpec = KyberParameterSpec.kyber1024;
                this.pqcParameterSpecs = "KYBER1024";
            }        
        }
    }

    @Override
    public KyberParameterSpec getKyberParameterSpec() {
        return kyberParameterSpec;
    }
    
    
}
