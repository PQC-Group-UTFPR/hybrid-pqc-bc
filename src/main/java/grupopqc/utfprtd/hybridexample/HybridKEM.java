package grupopqc.utfprtd.hybridexample;

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
 * Hybrid Concrete Strategy class.
 * //TODO: function to search and map algorithm name to ParameterSpec Object
 * //TODO: map PQC level to Classical Level for the algorithm parameter spec (e.g., Kyber768-with-P384)
 * //TODO: Map agreement type with the prev. keygen. types
 * //TODO: UKM (user keying material) as a parameter
 * //TODO: BC provider names. BCFIPS 1.77 seems to include PQC (so we could use only one provider instead of two)
 */
public class HybridKEM implements KeyEstablishmentStrategy {

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

            //generate a classic key
            //TODO: map PQC level to Classical Level for the algorithm parameter spec (e.g., Kyber768-with-P384)
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-384");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
            g.initialize(ecSpec, new SecureRandom());
            KeyPair aKeyPair = g.generateKeyPair();

            r.put("Classical", aKeyPair);
            r.put("KEM", kp);
            

            return r;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
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

            //PQC encaps
            byte[] encapsulatedKey = secEnc1.getEncapsulation();
            //get K from PQC KEM
            byte[] K = secEnc1.getEncoded();                        
            

            //Hybrid Part
            //TODO: Map agreement type with the prev keygen types
            KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BC");
            
            
            //Z' = Z concat K  
            PrivateKey privateKey = keys.get("Classical").getPrivate();
            PublicKey otherPartyPublicKey = keys.get("OtherParty-Classical").getPublic();
            agreement.init(privateKey, new HybridValueParameterSpec(K, new UserKeyingMaterialSpec(ukm)));
            agreement.doPhase(otherPartyPublicKey, true);

            SecretKey agreedKey = agreement.generateSecret(encAlgoName);
            
            r.put("C", encapsulatedKey);
            r.put("K", agreedKey.getEncoded());
                       
            return r;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
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
            
            //Hybrid Part
            //TODO: Map agreement type with the prev keygen types
            KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BC");

            //Z' = Z concat K  
            PrivateKey privateKey = keys.get("Classical").getPrivate();
            PublicKey otherPartyPublicKey = keys.get("OtherParty-Classical").getPublic();
            agreement.init(privateKey, new HybridValueParameterSpec(K, new UserKeyingMaterialSpec(ukm)));
            agreement.doPhase(otherPartyPublicKey, true);

            SecretKey agreedKey = agreement.generateSecret(encAlgoName);
            
            return agreedKey.getEncoded();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {            
            return null;
        }
    }

}
