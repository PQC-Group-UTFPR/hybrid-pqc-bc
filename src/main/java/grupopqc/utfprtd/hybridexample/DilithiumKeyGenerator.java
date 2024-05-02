package grupopqc.utfprtd.hybridexample;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;

import java.security.SecureRandom;
import java.util.ArrayList;

public class DilithiumKeyGenerator {

    public ArrayList<Object> listKeyPair(AsymmetricCipherKeyPair keyPair, DilithiumPublicKeyParameters PKParam){

            ArrayList<Object> listgetArray = new ArrayList<>();

            listgetArray.add(keyPair);
            listgetArray.add(PKParam);

            return listgetArray;
        }

    public ArrayList<Object> generateDilithiumKeyPair() {

        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
        //chamar a classe para gerar o arraylist

        SecureRandom srandom = new SecureRandom();

        keyGen.init(new DilithiumKeyGenerationParameters(srandom, DilithiumParameters.dilithium2));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        DilithiumPublicKeyParameters pkParam = (DilithiumPublicKeyParameters) keyPair.getPublic();

        return listKeyPair(keyPair, pkParam);

    }

}