package grupopqc.utfprtd.hybridexample.Algorithms;


import grupopqc.utfprtd.hybridexample.HybridSignatureExample;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.UnsupportedEncodingException;
import java.security.Security;
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

        SignerStrategy strategy;

        System.out.println("Starting key generator tests on PQC only with Dilithium");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium2");

        long startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            strategy = new PQSigner();
            runKeyGen(strategy, "Dilithium2");
        }
        long endTime = System.currentTimeMillis();
        long elapsedTime = endTime - startTime;
        long minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium2");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium3");

        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            strategy = new PQSigner();
            runKeyGen(strategy, "Dilithium3");
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
            strategy = new PQSigner();
            runKeyGen(strategy, "Dilithium5");
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium5");
        System.out.println("End of key generator tests.");

        System.out.println();
        System.out.println("Starting signing tests");

        System.out.println("--------Initiating test--------");
        System.out.println("Stating tests with Dilithium2");
        startTime = System.currentTimeMillis();
        for (int i = 0; i < keyNumbers; i++) {
            strategy = new PQSigner();
            runSigner(strategy, message, "Dilithium2");
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
            strategy = new PQSigner();
            runSigner(strategy, message, "Dilithium3");
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
            strategy = new PQSigner();
            runSigner(strategy, message, "Dilithium5");
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
            strategy = new PQSigner();
            runVerify(strategy, message, "Dilithium2");
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
            strategy = new PQSigner();
            runVerify(strategy, message, "Dilithium3");
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
            strategy = new PQSigner();
            runVerify(strategy, message, "Dilithium5");
        }
        endTime = System.currentTimeMillis();
        elapsedTime = endTime - startTime;
        minutesElapsed = TimeUnit.MILLISECONDS.toSeconds(elapsedTime);
        System.out.println("Elapsed time: " + minutesElapsed + " seconds");
        System.out.println("Ending tests with Dilithium5");

    }

    private static void runKeyGen(SignerStrategy strategy, String DilithiumLevel)  {
            strategy.init(DilithiumLevel);
    }

    private static void runSigner(SignerStrategy strategy, String message, String DilithiumLevel){

        strategy.init(DilithiumLevel);

        try{
            byte[] s = message.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void runVerify(SignerStrategy strategy, String message, String DilithiumLevel){

        try {
            strategy.init(DilithiumLevel);

            byte[] signed = message.getBytes("UTF-8");

            strategy.verify(message.getBytes("UTF-8"), signed);

        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
