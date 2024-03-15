package grupopqc.utfprtd.hybridexample.Utils;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

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

}
