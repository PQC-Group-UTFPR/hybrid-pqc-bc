/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package x509;

import grupopqc.utfprtd.hybridexample.RSA;
import java.io.StringWriter;
import java.security.KeyPair;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 *
 * @author alexandregiron
 * based on https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-keys-05.txt
 * and https://github.com/EntrustCorporation/draft-ounsworth-pq-composite-keys/tree/master/sampledata/current
 * 
 */
public class CompositeExample {
    
    public static void main(String[] args) throws Exception{
        
        KeyPair classicKeyPair = RSA.generateKeyPair();        
        //Create a composite private key
        
        //create a composite public key        
        CompositePublicKey compositePk = new CompositePublicKey();
        compositePk.AddComponent(classicKeyPair);
        
        //test: save composite PK
        compositePk.CompositeToPEM();
        
        //create a composite signature
        
        //TODO: Create a x509 composite certificate example.
    }
}
