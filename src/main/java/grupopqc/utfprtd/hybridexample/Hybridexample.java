package grupopqc.utfprtd.hybridexample;

import java.util.HashMap;
import java.util.Map;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

/**
 * It follows (as possible) SP80056C style from https://www.youtube.com/watch?v=EABttUCoTdY
 * 1. KeyGen operations (Alice and Bob)
 * 1.1 Public Key Distribution: Parties add Other Party's Public Keys into its own set of keys
 * 2. Encapsulation
 * 3. Decapsulation
 */
public class Hybridexample {

    static PublicKey PublicKeyReceiver;
    static byte[] ukm = new byte[32]; 
    
    public static void main(String[] args) {
        System.out.println("(Hybrid) PQC Key-Establishment Example with Bouncy Castle");
        
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(ukm);
        
        //run(false);
        KeyEstablishmentStrategy strategy;
        if (args.length == 0){ 
            strategy = new HybridKEM();
            System.out.println("\tPQC KEM in Hybrid mode selected (default)");
        }else{
            strategy = new KEM();
            System.out.println("\tPQC-Only KEM selected");            
        }
        runKeyEstablishment(strategy);
    }

    private static void runKeyEstablishment(KeyEstablishmentStrategy s){
        
        //Select algorithms
        String algoName = "KYBER";
        String providerName = "BCPQC";
        String encName = "AES[256]";
        
        //Alice is the initiator; Bob replies
        //1.Generate Keys
        Map<String, KeyPair> AliceKeys = s.keyGeneration(algoName, providerName);
        Map<String, KeyPair> BobKeys = s.keyGeneration(algoName, providerName);
        if (AliceKeys.isEmpty() || BobKeys.isEmpty()) {
            System.out.println("\tFailed Key generation");
            System.exit(1);
        }
        
        //Key Distribution:
        Map<String, KeyPair> AlicePulicKeys = new HashMap<>();
        Map<String, KeyPair> BobPulicKeys = new HashMap<>();
        
        //Alice sends its public key(s) to Bob. So here we add public keys in the mappings        
        for (String key : AliceKeys.keySet()) {
            KeyPair k = new KeyPair(AliceKeys.get(key).getPublic(), null);
            AlicePulicKeys.put("OtherParty-"+key, k);            
        }
        //Alice receives Bobs Public Keys
        for (String key : BobKeys.keySet()) {
            KeyPair k = new KeyPair(BobKeys.get(key).getPublic(), null);
            BobPulicKeys.put("OtherParty-"+key, k);            
        }
        AliceKeys.putAll(BobPulicKeys);
        BobKeys.putAll(AlicePulicKeys);
        //At the end, parties have their own keypairs + public keys of each other
                
                
        //2. Bob Perform Encaps to AlicePublicKeys
        Map rEncaps = s.encapsulation(algoName, providerName, encName, BobKeys);
        if (rEncaps.isEmpty()) {
            System.out.println("\tFailed Encaps");
            System.exit(2);
        }
        byte[] C = (byte[]) rEncaps.get("C");
        byte[] K = (byte[]) rEncaps.get("K");
        
        //3. Alice Perform Decaps
        byte[] decryptedK = (byte[]) s.decapsulation(algoName, providerName, encName, C, AliceKeys);
        boolean keysAreEqual = Arrays.areEqual(K, decryptedK);
        if (keysAreEqual){
            System.out.println("\tKey-Establishment success!");
        }else {
            System.out.println("\tFailed Decaps");
            System.exit(2);
        }
    }    

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
       
}
