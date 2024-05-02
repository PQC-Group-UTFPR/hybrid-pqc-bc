package grupopqc.utfprtd.hybridexample;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

import java.util.ArrayList;


/**
 *
 * @author alexandregiron
 */
public interface SignerStrategy {

    public ArrayList<MessageSigner> init(boolean keyUsageForSigning1, boolean keyUsageForSigning2, ArrayList<CipherParameters> parameters);

    byte[] sign(MessageSigner ms, byte[] message);

    boolean verify(MessageSigner ms, byte[] message, byte[] signature);
}
