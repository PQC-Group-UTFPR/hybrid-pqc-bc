/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package x509;

import grupopqc.utfprtd.hybridexample.RSA;
import java.security.KeyPair;

/**
 *
 * @author alexandregiron
 * based on https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-keys-05.txt
 * and https://github.com/EntrustCorporation/draft-ounsworth-pq-composite-keys/tree/master/sampledata/current
 * 
 */
public class CompositeExample {
    
    public static void main() throws Exception{
        //Create a composite private key
        KeyPair classicKeyPair = RSA.generateKeyPair();
        
        
        
        //create a composite public key
        
        
        
        //create a composite signature
        
        //TODO: Create a x509 composite certificate example.
    }
}
