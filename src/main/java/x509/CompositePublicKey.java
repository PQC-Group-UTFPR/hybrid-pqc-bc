/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package x509;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

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
    //TODO: env variable for this
    public static int maxComponents = 2;
    private ArrayList <SubjectPublicKeyInfo> compositePublicKey;

    public void AddComponent(KeyPair keyPair){
        //create a subject public key info and adds to the class        
        byte[] keyBytes = keyPair.getPublic().getEncoded();         
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyBytes));        
        this.compositePublicKey.add(subjectPublicKeyInfo);
    }
    
    public void CompositeToASNObjects(){
        for (SubjectPublicKeyInfo obj: this.compositePublicKey){
            
            ASN1BitString keyBitString = obj.getPublicKeyData();
            //ASN1AlgorithmIdentifier oid = (ASN1ObjectIdentifier)obj.getAlgorithm();
            //oid.toString();
            //DERSequence seq = new DERSequence()
        }
        
        
        
    }
    
    public void CompositeToPEM() {
        //Creates a PEM and shows it in the screen. TODO: iterate the list, probably needs to merge the ASN1 sequences        
        
        
        try {
            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);
            pemWriter.writeObject(new PemObject("PUBLIC KEY", this.compositePublicKey.getFirst().getEncoded()));
            pemWriter.flush();
            pemWriter.close();
            System.out.println(writer.toString());
        } catch (IOException ex) {
            Logger.getLogger(CompositePublicKey.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public CompositePublicKey() {
        this.compositePublicKey = new ArrayList<>();
    }

    public ArrayList<SubjectPublicKeyInfo> getCompositePublicKey() {
        return compositePublicKey;
    }

    public void setCompositePublicKey(ArrayList<SubjectPublicKeyInfo> compositePublicKey) {
        this.compositePublicKey = compositePublicKey;
    }
    
    /*
    Example:
SubjectPublicKeyInfo SEQUENCE (2 elem)
  algorithm AlgorithmIdentifier SEQUENCE (1 elem)
    algorithm OBJECT IDENTIFIER 2.16.840.1.114027.80.5.1
  subjectPublicKey BIT STRING (16568 bit) 00110000100000100000100000010011001100001000001000000111101101000011…
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        SEQUENCE (1 elem)
          OBJECT IDENTIFIER 1.3.6.1.4.1.2.267.11.6.5
        BIT STRING (15616 bit) 11011011000000010000100000110100111010000001011111111011010000001101…
      SEQUENCE (2 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
          OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
        BIT STRING (520 bit) 0000010011001011010000100000010100101101111000111010000110000110011011…
    
    
    */
    
}
