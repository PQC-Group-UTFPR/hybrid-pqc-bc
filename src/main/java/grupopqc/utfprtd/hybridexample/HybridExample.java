package grupopqc.utfprtd.hybridexample;

import java.security.*;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import grupopqc.utfprtd.hybridexample.Algorithms.HybridKEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KeyEstablishmentStrategy;
import grupopqc.utfprtd.hybridexample.Utils.Utils;
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
public class HybridExample {

    private static final Logger LOGGER = Logger.getLogger(HybridExample.class.getName());
    static PublicKey PublicKeyReceiver;
    private static final String securityProviderName = "BC";
    private static final String pqcSecurityProviderName = "BCPQC";
    public static byte[] ukm = new byte[32];
    
    public static void main(String[] args) {
        LOGGER.log(Level.INFO, "(Hybrid) PQC Key-Establishment Example with Bouncy Castle");

        if (Security.getProvider(pqcSecurityProviderName) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(securityProviderName) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(ukm);
        
        //run(false);
        KeyEstablishmentStrategy strategy;
        if (args.length == 0){ 
            strategy = new HybridKEM();
            LOGGER.log(Level.INFO, "PQC KEM in Hybrid mode selected (default)");
        }else{
            strategy = new KEM();
            LOGGER.log(Level.INFO, "PQC-Only KEM selected");
        }
        runKeyEstablishment(strategy);
    }

    private static void runKeyEstablishment(KeyEstablishmentStrategy strategy){
        //Alice is the initiator; Bob replies

        String encName = "AES[256]";
        strategy.setPqcParameterSpecs("KYBER512");
        strategy.setProviderName("BCPQC");

        //1 - GENERATE KEYS
        LOGGER.log(Level.INFO, "Generate keys");
        Map<String, KeyPair> aliceKeys = strategy.keyGeneration();
        Map<String, KeyPair> bobKeys = strategy.keyGeneration();
        if (aliceKeys.isEmpty() || bobKeys.isEmpty()) {
            LOGGER.log(Level.SEVERE, "Failed Key generation");
            System.exit(1);
        }

        //2 - PUBLIC KEY SHARING
        LOGGER.log(Level.INFO, "Public key sharing");
        aliceKeys.putAll(Utils.getKeyPublicList(bobKeys));//Alice receives Bobs Public Keys
        bobKeys.putAll(Utils.getKeyPublicList(aliceKeys));//Bobo receives Alice Public Keys

        //3 - BOB PERFORM ENCAPS TO ALICE PUBLIC KEYS
        LOGGER.log(Level.INFO, "Bob perform emcaps to alice plubic keys");
        Map<String, byte[]> secretEmcapsuledMap = strategy.encapsulation(encName, bobKeys);
        if (secretEmcapsuledMap.isEmpty()) {
            LOGGER.log(Level.SEVERE,"Failed Encaps");
            System.exit(2);
        }
        byte[] encapsulatedSecret = (byte[]) secretEmcapsuledMap.get("C");
        byte[] secretKey = (byte[]) secretEmcapsuledMap.get("K");

        //4 - ALICE PERFORM DECAPS
        LOGGER.log(Level.INFO, "Alice perform decaps");
        byte[] decryptedKey = (byte[]) strategy.decapsulation(encName, encapsulatedSecret, aliceKeys);
        boolean keysAreEqual = Arrays.areEqual(secretKey, decryptedKey);
        if (keysAreEqual){
            LOGGER.log(Level.INFO, "Key-Establishment success!");
        }else {
            LOGGER.log(Level.SEVERE, "Failed Decaps");
            System.exit(2);
        }
    }

}
