package grupopqc.utfprtd.hybridexample;

import static java.nio.charset.StandardCharsets.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;


public class RSA {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static int KeySize = 2048;

    public static boolean bytesToBoolean(byte[] buffer) {
        return bytesToBoolean(buffer);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KeySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        setPrivateKey(pair.getPrivate());
        setPublicKey(pair.getPublic());
        return pair;
    }

    public static String sign(String message) throws Exception {
        Signature privateSign = Signature.getInstance("SHA256WithRSA");
        privateSign.initSign(privateKey);
        privateSign.update(message.getBytes(UTF_8));
        byte[] signature = privateSign.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verify(String signedMessage, String plainText) throws Exception {
        Signature publicSign = Signature.getInstance("SHA256withRSA");
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
