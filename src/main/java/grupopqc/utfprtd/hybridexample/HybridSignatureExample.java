package grupopqc.utfprtd.hybridexample;

import grupopqc.utfprtd.hybridexample.Algorithms.PQSigner;
import grupopqc.utfprtd.hybridexample.Algorithms.HybridSigner;
import grupopqc.utfprtd.hybridexample.Algorithms.SignerStrategy;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;


public class HybridSignatureExample {
    public static void main(String[] args) {
        System.out.println("(Hybrid) PQC Key-Establishment Example with Bouncy Castle");

        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        SignerStrategy strategy;
        if (args.length == 0){
            strategy = new HybridSigner();            
            System.out.println("\t\tPQC Signer in Hybrid mode selected (default)\n");
        }else{
            strategy = new PQSigner();
            System.out.println("\t\tPQC-Only Signer selected\n");
        }
        runSigner(strategy);

    }


    private static void runSigner(SignerStrategy strategy)  {
       
        try{

            String message = "Hello world of PQC signers";
            //INIT
            strategy.init("Dilithium2");

            //SIGN
            byte[] s = strategy.sign(message.getBytes("UTF-8"));
            System.out.println("Signature produced:" + Base64.getEncoder().encodeToString(s));

            //test integrity
            //s[0] = '\0';

            if (strategy.verify(message.getBytes("UTF-8"), s, null)){
                System.out.println("Valid Signature");
            } else{
                System.out.println("InvalidSignature");
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }


    }

}
