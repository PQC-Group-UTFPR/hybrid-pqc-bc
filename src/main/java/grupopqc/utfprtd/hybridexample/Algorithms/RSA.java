package grupopqc.utfprtd.hybridexample.Algorithms;

import static java.nio.charset.StandardCharsets.*;

import java.security.*;
import java.util.Base64;



public class RSA {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static int KeySize = 2048;

    //Maybe we can ommit and return void
    public static KeyPair generateKeyPair(int keysize) throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        
        if (keysize < 2048){
            System.out.println("Error: invalid RSA keysize");
            return null;
        }
        
        KeySize = keysize;        
        generator.initialize(KeySize);

        KeyPair pair = generator.generateKeyPair();

        setPrivateKey(pair.getPrivate());
        setPublicKey(pair.getPublic());

        return pair;
    }

    //@Override
    public String sign(String message) throws Exception {
        Signature privateSign = Signature.getInstance("SHA256WithRSA");         //TODO: change this to a parameter/attribute
        privateSign.initSign(privateKey);
        privateSign.update(message.getBytes(UTF_8));
        byte[] signature = privateSign.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

   // @Override
    public boolean verify(String signedMessage, String plainText) throws Exception {
        Signature publicSign = Signature.getInstance("SHA256withRSA");           //TODO: same
        publicSign.initVerify(publicKey);
        publicSign.update(plainText.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signedMessage);
        return publicSign.verify(signatureBytes);
    }

    public static PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static void setPrivateKey(PrivateKey privateKey) {
        RSA.privateKey = privateKey;
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }

    public static void setPublicKey(PublicKey publicKey) {
        RSA.publicKey = publicKey;
    }

    public static int getKeySize() {
        return KeySize;
    }

    public static void setKeySize(int KeySize) {
        RSA.KeySize = KeySize;
    }
}