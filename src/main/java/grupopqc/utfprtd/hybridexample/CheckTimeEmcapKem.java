package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.Algorithms.HybridKEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KeyEstablishmentStrategy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyPair;
import java.security.Security;
import java.util.Map;

public class CheckTimeEmcapKem {

    private static final int numChaves = 10000000;
    private static final String securityProviderName = "BC";
    private static final String pqcSecurityProviderName = "BCPQC";

    public static void main(String[] args){
        System.out.println("numero de chaves geradas: " + numChaves);
        if (Security.getProvider(pqcSecurityProviderName) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(securityProviderName) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyEstablishmentStrategy strategy = new KEM();

        System.out.println("===== teste com kem ======");
        System.out.println("Inicio do teste (Kyber 512):");
        strategy.setPqcParameterSpecs("KYBER512");
        strategy.setProviderName("BCPQC");
        long startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");


        System.out.println("Inicio do teste (Kyber 768):");
        strategy.setPqcParameterSpecs("KYBER768");
        strategy.setProviderName("BCPQC");
        startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");

        System.out.println("Inicio do teste (Kyber 1024):");
        strategy.setPqcParameterSpecs("KYBER1024");
        strategy.setProviderName("BCPQC");
        startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");


        System.out.println("===== teste com kem hibrido ======");
        strategy = new HybridKEM();
        System.out.println("Inicio do teste (Kyber 512):");
        strategy.setPqcParameterSpecs("KYBER512");
        strategy.setProviderName("BCPQC");
        startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");


        System.out.println("Inicio do teste (Kyber 768):");
        strategy.setPqcParameterSpecs("KYBER768");
        strategy.setProviderName("BCPQC");
        startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");


        System.out.println("Inicio do teste (Kyber 1024):");
        strategy.setPqcParameterSpecs("KYBER1024");
        strategy.setProviderName("BCPQC");
        startTime = System.currentTimeMillis();
        for (int a = 0; a < numChaves; a++){
            Map<String, KeyPair> keyPair = strategy.keyGeneration();
            keyPair.clear();
        }
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        System.out.println("duração: " + duration/60000 + " min");
        System.out.println("Fim do test:");

    }
}
