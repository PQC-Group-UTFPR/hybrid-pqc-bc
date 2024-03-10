package grupopqc.utfprtd.hybridexample;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    static public boolean bytesToBoolean(byte[] buffer){
        return bytesToBoolean(buffer);
    }

    public RSA() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();

        } catch (Exception ignored) {
        }
    }

    public String sign(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signedBytes = cipher.doFinal(messageToBytes);
        return encode(signedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public boolean verify(String signedMessage) throws Exception {
        byte[] signedBytes = decode(signedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] verifiedMessage = cipher.doFinal(signedBytes);
        return bytesToBoolean(verifiedMessage);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
