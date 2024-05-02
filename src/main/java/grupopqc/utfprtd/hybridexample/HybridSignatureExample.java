package grupopqc.utfprtd.hybridexample;

import static grupopqc.utfprtd.hybridexample.HybridExample.ukm;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;


/**
 *
 * @author alexandregiron
 */
public class HybridSignatureExample {
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
        SignerStrategy strategy;
        if (args.length == 0){
            strategy = new HybridPQSigner();                        
            System.out.println("\tPQC Signer in Hybrid mode selected (default)");
        }else{
            strategy = new PQSigner();
            System.out.println("\tPQC-Only Signer selected");
        }
        runSigner(strategy);

    }


    private static void runSigner(SignerStrategy strategy)  {

        DilithiumKeyGenerator keyPair = new DilithiumKeyGenerator();

        // CipherParameters dspec = (CipherParameters) DilithiumParameterSpec.dilithium2;
        CipherParameters dspec;
        //DilithiumParameters dparams = ;
        /*
        DilithiumParameters dilithiumParams = (DilithiumParameters)DilithiumParameters.dilithium2;
        dspec = new DilithiumKeyParameters(false,dilithiumParams);
*/
        /*try {
            DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)PublicKeyFactory.createKey(
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((DilithiumPublicKeyParameters)keyPair.getPublic()));
        */

        try{
            DilithiumKeyGenerator pkParam = new DilithiumKeyGenerator();

            DilithiumPrivateKeyParameters skParam = (DilithiumPrivateKeyParameters)keyPair.getPrivate();


            String message = "Hello world of PQC signers";
            //INIT
            MessageSigner ms = strategy.init(true, skParam);


            //sign
            byte[] s = strategy.sign(ms, message.getBytes("UTF-8"));

            System.out.println("Signature produced:" + Base64.getEncoder().encodeToString(s));

            //test integrity
            //s[0] = '\0';

            //MessageSigner ms2 = strategy.init(false, pubParams);
            MessageSigner ms2 = strategy.init(false, true, pkParam);


            if (strategy.verify(ms2, message.getBytes("UTF-8"), s)){
                System.out.println("Valid Signature");
            } else{
                System.out.println("InvalidSignature");
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }/* catch (IOException ex) {
            Logger.getLogger(HybridSignatureExample.class.getName()).log(Level.SEVERE, null, ex);
        }*/


    }

}