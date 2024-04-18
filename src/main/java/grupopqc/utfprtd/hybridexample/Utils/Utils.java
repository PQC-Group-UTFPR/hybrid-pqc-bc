package grupopqc.utfprtd.hybridexample.Utils;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class Utils {

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static Map<String, KeyPair> getKeyPublicList(Map<String, KeyPair> keys){
        Map<String, KeyPair> keyPairMap = new HashMap<>();
        for (String key : keys.keySet()) {
            KeyPair keyPublic = new KeyPair(keys.get(key).getPublic(), null);
            keyPairMap.put("OtherParty-"+key, keyPublic);
        }
        return keyPairMap;
    }
    
    public static String toPEM(java.security.cert.X509Certificate cert) throws IOException {
        StringWriter stringWriter = null;
        JcaPEMWriter pemWriter = null;
        String result = null;
        try {
            stringWriter = new StringWriter();
            pemWriter = new JcaPEMWriter(stringWriter);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            stringWriter.flush();
            result = stringWriter.toString();
        } finally {
            if (pemWriter != null)
                pemWriter.close();
            if (stringWriter != null)
                stringWriter.close();
        }
        return result;
    }

}
