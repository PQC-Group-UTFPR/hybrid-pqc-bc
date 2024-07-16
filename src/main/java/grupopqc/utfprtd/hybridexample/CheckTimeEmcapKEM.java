package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.Algorithms.HybridKEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KeyEstablishmentStrategy;
import grupopqc.utfprtd.hybridexample.Utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyPair;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class CheckTimeEmcapKEM {

    private static final String securityProviderName = "BC";
    private static final String pqcSecurityProviderName = "BCPQC";
    private static KeyEstablishmentStrategy strategy = new KEM();
    private static String encName = "AES[256]";

    public static void main(String[] args){
        if (Security.getProvider(pqcSecurityProviderName) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(securityProviderName) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        int limite = 10000000;

        List<Integer> listaTestes = Stream.iterate(10, n -> n <= limite, n -> n * 10).toList();

        //testgenarateKeys(listaTestes);
        //testEmcapKeys(listaTestes);
        testDemcapKeys(listaTestes);
    }

    private static void testgenarateKeys(List<Integer> listaTestes){
        System.out.println("## teste de geração de chaves ##");
        strategy = new KEM();
        startGenerateKeysTest("KYBER512", "BCPQC", listaTestes, "genarate-keys-pqc");
        startGenerateKeysTest("KYBER768", "BCPQC", listaTestes, "genarate-keys-pqc");
        startGenerateKeysTest("KYBER1024", "BCPQC", listaTestes, "genarate-keys-pqc");
        strategy = new HybridKEM();
        startGenerateKeysTest("KYBER512", "BCPQC", listaTestes, "genarate-keys-hybrid");
        startGenerateKeysTest("KYBER768", "BCPQC", listaTestes, "genarate-keys-hybrid");
        startGenerateKeysTest("KYBER1024", "BCPQC", listaTestes, "genarate-keys-hybrid");
    }

    private static void testEmcapKeys(List<Integer> listaTestes) {
        System.out.println("## teste para emcap de chaves ##");
        strategy = new KEM();
        startEmcapkeys("KYBER512", "BCPQC", listaTestes, "emcap-Keys-pqc");
        startEmcapkeys("KYBER768", "BCPQC", listaTestes, "emcap-Keys-pqc");
        startEmcapkeys("KYBER1024", "BCPQC", listaTestes, "emcap-Keys-pqc");
        strategy = new HybridKEM();
        startEmcapkeys("KYBER512", "BCPQC", listaTestes, "emcap-Keys-hybrid");
        startEmcapkeys("KYBER768", "BCPQC", listaTestes, "emcap-Keys-hybrid");
        startEmcapkeys("KYBER1024", "BCPQC", listaTestes, "emcap-Keys-hybrid");
    }

    private static void testDemcapKeys(List<Integer> listaTestes) {
        System.out.println("## teste para demcap de chaves ##");
        strategy = new KEM();
        startDemcapkeys("KYBER512", "BCPQC", listaTestes, "demcap-Keys-pqc");
        startDemcapkeys("KYBER768", "BCPQC", listaTestes, "demcap-Keys-pqc");
        startDemcapkeys("KYBER1024", "BCPQC", listaTestes, "demcap-Keys-pqc");
        strategy = new HybridKEM();
        startDemcapkeys("KYBER512", "BCPQC", listaTestes, "demcap-Keys-hybrid");
        startDemcapkeys("KYBER768", "BCPQC", listaTestes, "demcap-Keys-hybrid");
        startDemcapkeys("KYBER1024", "BCPQC", listaTestes, "emcap-Keys-hybrid");
    }

    private static void startGenerateKeysTest(String parameterSpecs, String providerName, List<Integer> listaTestes, String type){
        strategy.setPqcParameterSpecs(parameterSpecs);
        strategy.setProviderName(providerName);

        for (Integer numGeradas : listaTestes){
            long startTime = System.currentTimeMillis();
            for (int a = 0; a < numGeradas; a++){
                Map<String, KeyPair> keyPair = strategy.keyGeneration();
                keyPair.clear();
            }
            long endTime = System.currentTimeMillis();
            long duration = (endTime - startTime);
            //System.out.println("duração: " + (double) numChaves / duration + " keys/min");
            System.out.println(parameterSpecs+";"+providerName+";"+numGeradas+";"+ (duration/1000.0) +";"+type);
        }

    }

    private static void startEmcapkeys(String parameterSpecs, String providerName, List<Integer> listaTestes, String type){
        strategy.setPqcParameterSpecs(parameterSpecs);
        strategy.setProviderName(providerName);

        Map<String, KeyPair> aliceKeys = strategy.keyGeneration();
        Map<String, KeyPair> bobKeys = strategy.keyGeneration();
        aliceKeys.putAll(Utils.getKeyPublicList(bobKeys));
        bobKeys.putAll(Utils.getKeyPublicList(aliceKeys));

        for (Integer numGeradas : listaTestes){
            long startTime = System.currentTimeMillis();
            for (int a = 0; a < numGeradas; a++){
                Map<String, byte[]> secretEmcapsuledMap = strategy.encapsulation(encName, bobKeys);
                secretEmcapsuledMap.clear();
            }
            long endTime = System.currentTimeMillis();
            long duration = (endTime - startTime);
            System.out.println(parameterSpecs+";"+providerName+";"+numGeradas+";"+ (duration/1000.0) +";"+type);
        }

    }

    private static void startDemcapkeys(String parameterSpecs, String providerName, List<Integer> listaTestes, String type){
        strategy.setPqcParameterSpecs(parameterSpecs);
        strategy.setProviderName(providerName);

        Map<String, KeyPair> aliceKeys = strategy.keyGeneration();
        Map<String, KeyPair> bobKeys = strategy.keyGeneration();
        aliceKeys.putAll(Utils.getKeyPublicList(bobKeys));
        bobKeys.putAll(Utils.getKeyPublicList(aliceKeys));

        Map<String, byte[]> secretEmcapsuledMap = strategy.encapsulation(encName, bobKeys);
        byte[] encapsulatedSecret = (byte[]) secretEmcapsuledMap.get("C");

        for (Integer numGeradas : listaTestes){
            long startTime = System.currentTimeMillis();
            for (int a = 0; a < numGeradas; a++){
                byte[] decryptedKey = (byte[]) strategy.decapsulation(encName, encapsulatedSecret, aliceKeys);
                decryptedKey = null;
            }
            long endTime = System.currentTimeMillis();
            long duration = (endTime - startTime);
            System.out.println(parameterSpecs+";"+providerName+";"+numGeradas+";"+ (duration/1000.0) +";"+type);
        }

    }

}
