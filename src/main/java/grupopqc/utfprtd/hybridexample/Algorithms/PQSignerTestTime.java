package grupopqc.utfprtd.hybridexample.Algorithms;


import grupopqc.utfprtd.hybridexample.HybridSignatureExample;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PQSignerTestTime {

    public static int keyNumbers = 100000;
    public static String message = "Hello world of PQC signers";

    public static void main(String[] args) {
        System.out.println("Initiating PQC Key-Establishment test time with Bouncy Castle for PQC only");

        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        SignerStrategy strategy = new PQSigner();

        System.out.println("Starting key generator tests on PQC only with Dilithium");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium2");

        long startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runKeyGen(strategy, "Dilithium2");
        }
        long endTime = System.currentTimeMillis();
        long elapsedTime = endTime - startTime;
        long minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Key generation elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium2");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium3");

        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runKeyGen(strategy, "Dilithium3");
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Key generation elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium3");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium5");

        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runKeyGen(strategy, "Dilithium5");
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Key generation elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium5");

        System.out.println();
        System.out.println("Starting signing tests");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium2");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runSigner(strategy, message);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium2");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium3");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runSigner(strategy, message);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium3");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium5");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runSigner(strategy, message);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium5");

        System.out.println("End of signing test");

        System.out.println();
        System.out.println("Starting test to verify the signature");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium2");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runVerify(strategy, message, null);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium2");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium3");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runVerify(strategy, message, null);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium3");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium5");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            runVerify(strategy, message, null);
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium5");

    }

    private static void runKeyGen(SignerStrategy strategy, String dilithiumLevel)  {
            strategy.init(dilithiumLevel);
    }

    private static void runSigner(SignerStrategy strategy, String message){
        try{
            byte[] s = strategy.sign(message.getBytes("UTF-8"));
            Base64.getEncoder().encodeToString(s);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void runVerify(SignerStrategy strategy, String message, String dilithiumLevel){

        try {
            byte[] signature = strategy.sign(message.getBytes("UTF-8"));
            strategy.verify(message.getBytes("UTF-8"), signature, dilithiumLevel);

        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
