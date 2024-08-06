package grupopqc.utfprtd.speedtesting;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import grupopqc.utfprtd.hybridexample.Algorithms.HybridKEM;
import grupopqc.utfprtd.hybridexample.Algorithms.KEM;
import grupopqc.utfprtd.hybridexample.Utils.HybridPenalty;
import grupopqc.utfprtd.hybridexample.Utils.Utils;

import java.util.ArrayList;

import java.util.Map;
import java.util.concurrent.Callable;
import org.bouncycastle.util.Arrays;

@Command(name = "bench", mixinStandardHelpOptions = true,
        version = "bench 1.0",
        description = "Benchmark of Hybrid PQC in Java.")
public class KEMSpeedTest implements Callable<Integer> {

    @Option(names = {"-m", "--main-pqc-algorithm"},
            description = "KYBER")
    private String algoName = "KYBER";
    @Option(names = {"-c", "--component-algorithm"},
            description = "NIST P-Curves, xECDH")
    private String componentAlgoName = "NIST P-Curves";

    
    public static void main(String[] args) {
        int exitCode = new CommandLine(new KEMSpeedTest()).execute(args);
        System.exit(exitCode);
    }
    
    @Override
    public Integer call() throws Exception {
        
        KEMTask tester = new KEMTask();               
        tester.initializeProviders();
        long siteration, stime;
        long operationTime, totalTime;
        stime = System.currentTimeMillis();        
        
        //comparing PQ-only vs Hybrids
        int numberOfparameterSets = 3; //TODO: get this from the BC algorithm classes
        int testSet = numberOfparameterSets * 2; //PQ-only and hybrid
             
        HybridPenalty p;
        ArrayList<HybridPenalty> penalties = new ArrayList<HybridPenalty>();                
        for (int i = 0; i < testSet; i++) {
                p = new HybridPenalty();
                if (i < testSet/2) {
                    tester.strategy = new KEM();
                } else {
                    tester.strategy = new HybridKEM();
                }
                tester.strategy.setPqcIDParameterSpecs(algoName, componentAlgoName, (i)%(numberOfparameterSets));
                tester.clearCounts();
                
                //setting attributes and checking for errors
                tester.alicekeys = tester.strategy.keyGeneration();
                tester.bobkeys = tester.strategy.keyGeneration();
                if (tester.alicekeys.isEmpty() || tester.bobkeys.isEmpty()) {
                    System.out.println("Failed Key generation");
                    System.exit(1);
                }
                
                tester.alicekeys.putAll(Utils.getKeyPublicList(tester.bobkeys));//Alice receives Bobs Public Keys
                tester.bobkeys.putAll(Utils.getKeyPublicList(tester.alicekeys));//Bob receives Alice Public Keys

                //run tests   
                System.out.println("===== Speed Testing " + tester.strategy.getClass().getSimpleName() + " ======");
                System.out.println("Testing " + tester.strategy.getKyberParameterSpec().getName() + " to execute " + Integer.toString(tester.iterations) + " iterations:");

                tester.option = 0;
                siteration = System.currentTimeMillis();
                tester.runKeyGen();
                operationTime = System.currentTimeMillis() - siteration;
                System.out.println("Time (ms):"+Long.toString(operationTime)+"\tKeyGens/s: " + Double.toString(tester.countKeyGens / (operationTime / 1000.0)));
                double keygenss = tester.countKeyGens / (operationTime / 1000.0);
                
                //checking for errors before testing encaps
                Map<String, byte[]> secretEncapsuledMap = tester.strategy.encapsulation(tester.encName, tester.bobkeys);
                if (secretEncapsuledMap.isEmpty()) {
                    System.out.println("Failed Encaps");
                    System.exit(2);
                }

                tester.option = 1;
                siteration = System.currentTimeMillis();
                tester.runEncaps();
                operationTime = System.currentTimeMillis() - siteration;
                System.out.println("Time (ms):"+Long.toString(operationTime)+"\tEncaps/s: " + Double.toString(tester.countEncaps / (operationTime / 1000.0)));
                double encapss =  tester.countEncaps / (operationTime / 1000.0);
                
                //setting attributes and checking for errors before decaps
                tester.encapsulatedSecret = (byte[]) secretEncapsuledMap.get("C");
                byte[] secretKey = (byte[]) secretEncapsuledMap.get("K");
                byte[] decryptedKey = (byte[]) tester.strategy.decapsulation(tester.encName, tester.encapsulatedSecret, tester.alicekeys);
                boolean keysAreEqual = Arrays.areEqual(secretKey, decryptedKey);
                if (!keysAreEqual) {
                    System.out.println("Failed Decaps");
                    System.exit(3);
                }
 
                tester.option = 2;
                siteration = System.currentTimeMillis();
                tester.runDecaps();
                operationTime = System.currentTimeMillis() - siteration;
                System.out.println("Time (ms):"+Long.toString(operationTime)+"\tDecaps/s: " + Double.toString(tester.countDecaps / (operationTime / 1000.0)));
                           
                double decapss = tester.countDecaps / (operationTime / 1000.0);
                if (i < testSet/2) {
                    p.setPenaltyKeyGen(keygenss);
                    p.setPenaltyEnc(encapss);
                    p.setPenaltyDec(decapss);
                }else{
                    p.setPenaltyKeyGen((  penalties.get((i)%(numberOfparameterSets)).getPenaltyKeyGen() / keygenss ) );
                    p.setPenaltyEnc(( penalties.get((i)%(numberOfparameterSets)).getPenaltyEnc() / encapss ));
                    p.setPenaltyDec((penalties.get((i)%(numberOfparameterSets)).getPenaltyDec() / decapss ));
                }                
                p.setAlgorithm(tester.strategy.getKyberParameterSpec().getName());
                penalties.add(p);                
        }
        totalTime = System.currentTimeMillis() - stime;
        System.out.println("RESULTS:");
        System.out.println("Total time (s): " + totalTime/1000.0);
        System.out.println("Hybrid Penalty (using the number of operations per second): ");
        System.out.print("\t\tKeygen Penalty: ");
        System.out.print("\tEncaps Penalty: ");
        System.out.print("\tDecaps Penalty: ");
        for (int i = penalties.size()/2 ; i < penalties.size(); i++){
            System.out.println("");
            p = penalties.get(i);
            System.out.print(p.getAlgorithm());            
            System.out.print("\t"+p.getPenaltyKeyGen()+"x "  );
            System.out.print("\t"+p.getPenaltyEnc()+"x " );
            System.out.print("\t"+p.getPenaltyDec()+"x "  );
        }                
    
        return 0;
    }   

}
