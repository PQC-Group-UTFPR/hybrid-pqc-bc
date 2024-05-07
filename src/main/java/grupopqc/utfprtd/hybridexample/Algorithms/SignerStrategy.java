package grupopqc.utfprtd.hybridexample.Algorithms;


/**
 *
 * @author alexandregiron
 */
public interface SignerStrategy {

    public void init(String pqAlgorithm);

    byte[] sign(byte[] message);

    boolean verify(byte[] message, byte[] signature);
}
