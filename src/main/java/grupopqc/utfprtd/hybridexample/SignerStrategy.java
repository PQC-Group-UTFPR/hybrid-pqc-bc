package grupopqc.utfprtd.hybridexample;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

import java.util.ArrayList;


/**
 *
 * @author alexandregiron
 */
public interface SignerStrategy {

    public MessageSigner init(boolean keyUsageForSigning, CipherParameters parameters);

    byte[] sign(MessageSigner ms, byte[] message);

    boolean verify(MessageSigner ms, byte[] message, byte[] signature);
}
