package grupopqc.utfprtd.hybridexample.Algorithms;

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
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
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
 * Hybrid Concrete Strategy class, using NIST P-Curves (P-256, P-384, P-521)
 * //TODO: function to search and map algorithm name to ParameterSpec Object  
 * //TODO: UKM (user keying material) as a parameter 
 * //TODO: BC provider names. BCFIPS 1.77 seems to include PQC (so we could use only one provider instead of two)
 */
public class HybridKEMECDH implements KeyEstablishmentStrategy {    
    private static final Logger LOGGER = Logger.getLogger(HybridKEMECDH.class.getName());
    private KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber768;
    private String providerClassicStrategy = "BC";
    private String algorithmClassicStrategy = "ECDH";
    private String pqcParameterSpecs;
    private String componentParameterSpec;
    private String componentParameterSpecHash;
    private String providerName = "BCPQC";
    byte[] ukm = new byte[32];

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    @Override
    public Map<String, KeyPair> keyGeneration() {
        Map<String, KeyPair> keyPairMap = new HashMap<>();
        try {
            // generate a PQC key
            KeyPairGenerator keyPairGeneratorPqc = KeyPairGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            KyberParameterSpec kyberParameterSpec = this.kyberParameterSpec;
            keyPairGeneratorPqc.initialize(kyberParameterSpec, new SecureRandom());
            KeyPair keyPairPqc = keyPairGeneratorPqc.generateKeyPair();
            keyPairMap.put("KEM", keyPairPqc);

            //generate a component key
            //if (componentParameterSpec.equals("xECDH")){
                
            //}else{
                ECParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(componentParameterSpec);
                KeyPairGenerator keyPairGeneratorClassic = KeyPairGenerator.getInstance(algorithmClassicStrategy, providerClassicStrategy);
                keyPairGeneratorClassic.initialize(ecNamedCurveParameterSpec, new SecureRandom());
                KeyPair keyPairClassic = keyPairGeneratorClassic.generateKeyPair();
                keyPairMap.put("Classical", keyPairClassic);
            //}

            return keyPairMap;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException err) {
            LOGGER.log(Level.SEVERE, err.toString());
            return keyPairMap;
        }
    }

    @Override
    public Map<String, byte[]> encapsulation(String encAlgoName, Map<String, KeyPair> keyPairMap) {
        KeyGenerator keyGenerator;
        String algorithm = componentParameterSpecHash;
        Map<String, byte[]> kemGeneratedMap = new HashMap<>();
        try {
            keyGenerator = KeyGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            PublicKey recipientPublicKey = keyPairMap.get("OtherParty-KEM").getPublic();

            //KEMGenerate Spec
            keyGenerator.init(new KEMGenerateSpec((PublicKey) recipientPublicKey, encAlgoName), new SecureRandom());
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();

            //PQC encaps
            byte[] encapsulatedSecret = secretKeyWithEncapsulation.getEncapsulation();
            byte[] key = secretKeyWithEncapsulation.getEncoded();

            //Hybrid Part
            KeyAgreement agreement = KeyAgreement.getInstance(algorithm, providerClassicStrategy);

            //Z' = Z concat K  
            PrivateKey privateKey = keyPairMap.get("Classical").getPrivate();
            PublicKey otherPartyPublicKey = keyPairMap.get("OtherParty-Classical").getPublic();
            agreement.init(privateKey, new HybridValueParameterSpec(key, new UserKeyingMaterialSpec(ukm)));
            agreement.doPhase(otherPartyPublicKey, true);

            SecretKey secretKey = agreement.generateSecret(encAlgoName);

            kemGeneratedMap.put("C", encapsulatedSecret);
            kemGeneratedMap.put("K", secretKey.getEncoded());

            return kemGeneratedMap;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException err) {
            LOGGER.log(Level.SEVERE, err.toString());
            return kemGeneratedMap;
        }
    }

    @Override
    public byte[] decapsulation(String encAlgoName, byte[] encapsulatedSecret, Map<String, KeyPair> keys) {
        KeyGenerator keyGenerator;
        String algorithm = componentParameterSpecHash;
        try {
            keyGenerator = KeyGenerator.getInstance(this.pqcParameterSpecs, this.providerName);
            //KEMExtract spec
            keyGenerator.init(new KEMExtractSpec((PrivateKey) keys.get("KEM").getPrivate(), encapsulatedSecret, encAlgoName), new SecureRandom());
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();

            byte[] kemDecaps = secretKeyWithEncapsulation.getEncoded();

            //Hybrid Part
            //TODO: Map agreement type with the prev keygen types
            KeyAgreement agreement = KeyAgreement.getInstance(algorithm, this.providerClassicStrategy);

            //Z' = Z concat K  
            PrivateKey privateKey = keys.get("Classical").getPrivate();
            PublicKey otherPartyPublicKey = keys.get("OtherParty-Classical").getPublic();
            agreement.init(privateKey, new HybridValueParameterSpec(kemDecaps, new UserKeyingMaterialSpec(ukm)));
            agreement.doPhase(otherPartyPublicKey, true);

            SecretKey agreedKey = agreement.generateSecret(encAlgoName);

            return agreedKey.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException err) {
            LOGGER.log(Level.SEVERE, err.toString());
            return null;
        }
    }

    public void setPqcParameterSpecs(String algorithm) {
        this.pqcParameterSpecs = algorithm;
        if (Objects.equals(algorithm, "KYBER512")) {
            this.kyberParameterSpec = KyberParameterSpec.kyber512;
            this.componentParameterSpec = "P-256";
            this.componentParameterSpecHash = "ECCDHWITHSHA256KDF";
        }
        if (Objects.equals(algorithm, "KYBER768")) {
            this.kyberParameterSpec = KyberParameterSpec.kyber768;
            this.componentParameterSpec = "P-384";
            this.componentParameterSpecHash = "ECCDHWITHSHA384KDF";
        }
        if (Objects.equals(algorithm, "KYBER1024")) {
            this.kyberParameterSpec = KyberParameterSpec.kyber1024;
            this.componentParameterSpec = "P-521";
            this.componentParameterSpecHash = "ECCDHWITHSHA512KDF";
        }
    }
    
    //IDs are to match the number of a test
    //This is actually just for the speed test class; the setPqcParameterSpecs() should be used instead
    @Override
    public void setPqcIDParameterSpecs(String algorithm, String componentAlgo, int ID) {
        if (algorithm.equals("KYBER") && componentAlgo.equals("NIST P-Curves")) {
            this.algorithmClassicStrategy = "ECDH";
            if (ID == 0) {
                this.kyberParameterSpec = KyberParameterSpec.kyber512;
                this.pqcParameterSpecs = "KYBER512";            
                this.componentParameterSpec = "P-256";
                this.componentParameterSpecHash = "ECCDHWITHSHA256KDF";
            }        
            
            if (ID == 1) {
                this.kyberParameterSpec = KyberParameterSpec.kyber768;
                this.pqcParameterSpecs = "KYBER768";
                this.componentParameterSpec = "P-384";
                this.componentParameterSpecHash = "ECCDHWITHSHA384KDF";
            }
            if (ID == 2) {
                this.kyberParameterSpec = KyberParameterSpec.kyber1024;
                this.pqcParameterSpecs = "KYBER1024";
                this.componentParameterSpec = "P-521";
                this.componentParameterSpecHash = "ECCDHWITHSHA512KDF";
            }
        }                
    }

    @Override
    public KyberParameterSpec getKyberParameterSpec() {
        return kyberParameterSpec;
    }

    
}
