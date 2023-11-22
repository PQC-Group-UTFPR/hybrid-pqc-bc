/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */


package grupopqc.utfprtd.hybridexample;



import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;





import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
//import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.Key;
import org.bouncycastle.crypto.asymmetric.AsymmetricECKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;

/*
* Based on here: https://stackoverflow.com/questions/75240825/implementing-crystals-kyber-using-bouncycastle-java
*/


/**
 *
 * @author alexandregiron
 * It follows (as possible) SP80056C style from https://www.youtube.com/watch?v=EABttUCoTdY
 */
public class Hybridexample {

    static PublicKey PublicKeyReceiver;
    static byte[] ukm = new SecureRandom().generateSeed(32);
    
    public static void main(String[] args) {
        System.out.println("Hello World!");
        
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        run(false);
    }

    private static void run(boolean b) {
        System.out.println("PQC Hybrid Example: Use this for testing purposes only...");
        /*KyberParameterSpec[] kyberParameterSpecs = {
                KyberParameterSpec.kyber512,
                KyberParameterSpec.kyber768,
                KyberParameterSpec.kyber1024
        };*/
        
        
        ////////////////////////////////////////////////////////////////////////
        // key-pair generation
        KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber768;
        String kyberParameterSpecName = kyberParameterSpec.getName();        
        System.out.println("Kyber KEM:" + kyberParameterSpecName);
        Map keys = generateHKyberKeyPair(kyberParameterSpec, true);

        if (keys.get("PQC") == null || keys.get("Classical") == null) {
            System.out.println("Failed Key generation");
            System.exit(1);
        }
        KeyPair pqcKeys = (KeyPair) keys.get("PQC");
        KeyPair classicalKeys = (KeyPair) keys.get("Classical");
        
        Map<String, PublicKey>  publickeys = new HashMap<>();
        publickeys.put("PQC", pqcKeys.getPublic());
        publickeys.put("Classical", classicalKeys.getPublic());
        
        //PublicKey publicKey = pqcKeys.getPublic();
        Map r = HEncapsulation(publickeys,true);
        byte[] C = (byte[]) r.get("C");
        byte[] K = (byte[]) r.get("K");
        
        PrivateKey privKey = pqcKeys.getPrivate();
        byte[] decryptedK = HDecapsulation(privKey, C,  classicalKeys.getPrivate(), true);

        //Check if decryption is equal
        System.out.println("Printing K(size:"+K.length+")"); //to be derived 
        System.out.println(bytesToHex(K));
        System.out.println("Decaps Result:");
        System.out.println(bytesToHex(decryptedK));
        
        boolean keysAreEqual = Arrays.areEqual(K, decryptedK);
        if (keysAreEqual){
            System.out.println("Decapsulation success!");
        }else {
            System.out.println("Failed Decaps");
            System.exit(2);
        }                                     
    }

            
    /*
    * Key pair generation
    * TODO: hybrid mode
    */    
    private static Map<String, KeyPair> generateHKyberKeyPair(KyberParameterSpec kyberParameterSpec, boolean isHybrid) {
        Map<String, KeyPair> r = new HashMap<>();
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
            kpg.initialize(kyberParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            
            r.put("PQC", kp);
            
            if (isHybrid){
                //generate a classic key
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-384"); 
                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
                g.initialize(ecSpec, new SecureRandom());
                KeyPair aKeyPair = g.generateKeyPair();
                r.put("Classical", aKeyPair);
            }
            
            return r;
            
            
            //alternate mode from tutorial
            //KyberKEMGenerator kyber = new KyberKEMGenerator(new SecureRandom());
            //return kyber;   
            
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    /*
    * Encaps
    * TODO: hybrid mode
    */
    
                     //K, C
    private static Map<String, byte[]> HEncapsulation(Map<String, PublicKey> keys, boolean isHybrid)  {
        KeyGenerator keyGen = null;
        Map<String, byte[]> r = new HashMap<>();
        try {            
            keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            //KEMGenerate Spec
            PublicKey publicKey = keys.get("PQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            
            //
            //SecretWithEncapsulation secEnc1 = (SecretWithEncapsulation) keyGen.generateKey();
            
            //PQC encaps
            byte[] encapsulatedKey = secEnc1.getEncapsulation();
            //get K from PQC KEM
            byte[] K = secEnc1.getEncoded();
            
            //Logs (optional)
            /*System.out.println("Printing Ciphertext(size:"+encapsulatedKey.length+")"); //to be derived 
            System.out.println(bytesToHex(encapsulatedKey));                        
            System.out.println("Printing K(size:"+K.length+")"); //to be derived 
            System.out.println(bytesToHex(K));*/
                                                                        
            //if is Hybrid...
            if (isHybrid){               
               KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BC");
               
                                
                //generate a classic key
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-384"); 
                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
                g.initialize(ecSpec, new SecureRandom());
                KeyPair aKeyPair = g.generateKeyPair();

                //hack: set public key receiver
                PublicKeyReceiver = aKeyPair.getPublic();
                
                
                //Z' = Z || K  
                publicKey = keys.get("Classical");
                agreement.init(aKeyPair.getPrivate(), new HybridValueParameterSpec(K, new UserKeyingMaterialSpec(ukm)));
                agreement.doPhase(publicKey, true);
                
                SecretKey agreedKey = agreement.generateSecret("AES[256]");
                r.put("K", agreedKey.getEncoded());
                                
            //----------------
            }else{
                r.put("K", K);
                                               
            }
            r.put("C", encapsulatedKey); 
            
            return r;                        
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private static byte[] HDecapsulation(PrivateKey pqcprivKey, byte[] C,PrivateKey classicalprivKey, boolean isHybrid) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            //KEMExtract spec
            keyGen.init(new KEMExtractSpec((PrivateKey) pqcprivKey, C, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            
            //logs (optional): show decrypted K
            byte[] K = secEnc2.getEncoded();
            /*System.out.println("Decaps Result:");
            System.out.println(bytesToHex(K));*/
            
                                                                                    
            //if is Hybrid...
            if (isHybrid){
                KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BC");
                //Generate a 'user' key material
                
                
                //Z' = K1 || K2  
                agreement.init(classicalprivKey, new HybridValueParameterSpec(K, new UserKeyingMaterialSpec(ukm)));
                agreement.doPhase(PublicKeyReceiver, true);
                
                SecretKey agreedKey = agreement.generateSecret("AES[256]");                
                return agreedKey.getEncoded();
            //----------------
            }
            
            
            return secEnc2.getEncoded(); //return K
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } 
    }
}
