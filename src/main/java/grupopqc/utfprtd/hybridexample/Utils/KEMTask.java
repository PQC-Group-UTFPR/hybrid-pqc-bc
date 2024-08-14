package grupopqc.utfprtd.hybridexample.Utils;

import grupopqc.utfprtd.hybridexample.Algorithms.KeyEstablishmentStrategy;
import java.security.KeyPair;
import java.security.Security;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class KEMTask  {
    public  String securityProviderName = "BC";
    public  String pqcSecurityProviderName = "BCPQC";                   
    
    public KeyEstablishmentStrategy strategy;
    public int iterations = 10;                //how many keys, encaps, decaps
    public Map<String, KeyPair> alicekeys;        //public for speed tests only!
    public Map<String, KeyPair> bobkeys;        //public for speed tests only!
    public String encName = "AES[256]";
    public byte[] encapsulatedSecret;

    public long countKeyGens = 0;
    public long countEncaps = 0;
    public long countDecaps = 0;
    public int option = 0;

    /*@Override
    public String call() throws Exception {
        switch (option) {
            case 1:
                runEncaps();
                break;
            case 2:
                runDecaps();
                break;
            default:
                runKeyGen();
        }

        return "All executions ended!";
    }*/

    public void runKeyGen() {
        for (int j = 0; j < this.iterations; j ++){                
            strategy.keyGeneration();
            countKeyGens++;
        }
    }

    public void runEncaps() {
        for (int j = 0; j < this.iterations; j ++){
            strategy.encapsulation(encName, bobkeys);
            countEncaps++;
        }
    }

    public void runDecaps() {
        for (int j = 0; j < this.iterations; j ++){
            strategy.decapsulation(encName, encapsulatedSecret, alicekeys);
            countDecaps++;
        }
    }
    
    
    public void initializeProviders() {                                
        if (Security.getProvider(this.pqcSecurityProviderName) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(this.securityProviderName) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }                
    }  
    
    public void clearCounts(){
        countKeyGens = 0;
        countEncaps = 0;
        countDecaps = 0;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }
    
    
}
