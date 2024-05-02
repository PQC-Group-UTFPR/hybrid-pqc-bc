package grupopqc.utfprtd.hybridexample;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

import javax.crypto.Cipher;
import java.util.ArrayList;

/**
 *
 * @author alexandregiron
 */
public class HybridSigner implements SignerStrategy{

    @Override
    public ArrayList<MessageSigner> init(boolean keyUsageForSigning1, boolean keyUsageForSigning2, ArrayList<CipherParameters> parameters) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public byte[] sign(MessageSigner ms, byte[] message) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public boolean verify(MessageSigner ms, byte[] message, byte[] signature) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}