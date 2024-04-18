/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package x509;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 *
 * @author alexandregiron
 
pk-Composite PUBLIC-KEY ::= {
       id id-composite-key
       KeyValue CompositePublicKey
       Params ARE ABSENT
       PrivateKey CompositePrivateKey
}
        
CompositePublicKey ::= SEQUENCE SIZE 
(2..MAX) OF SubjectPublicKeyInfo
                
CompositePrivateKey ::= SEQUENCE SIZE 
(2..MAX) OF OneAsymmetricKey
 */
public class CompositePublicKey {
    private SubjectPublicKeyInfo[] compositePublicKey;

    public CompositePublicKey(SubjectPublicKeyInfo[] compositePublicKey) {
        this.compositePublicKey = compositePublicKey;
    }

    public SubjectPublicKeyInfo[] getCompositePublicKey() {
        return compositePublicKey;
    }

    public void setCompositePublicKey(SubjectPublicKeyInfo[] compositePublicKey) {
        this.compositePublicKey = compositePublicKey;
    }            
    
}
