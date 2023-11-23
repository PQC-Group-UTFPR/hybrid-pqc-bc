package grupopqc.utfprtd.hybridexample;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 *
 * Strategy Pattern for the key establishment modes
 */
public interface KeyEstablishmentStrategy {
    /**
    * Generates KeyPair(s)
    * @param algorithmSpec the name of the algorithm based on the desired crypto. provider
    * @param providerName  the name of the (BC) provider.
    * @return              the map of keyPair(s) generated. The string part could be defined as "PQC", "Classical" for indexing modes.
    */
    Map<String, KeyPair> keyGeneration(String algorithmSpec, String providerName);   
    /**
    * Performs encapsulation (KEM.Encaps() style)
    * @param algorithmSpec the name of the algorithm based on the desired crypto. provider    
    * @param providerName  the name of the (BC) provider.
    * @param encAlgoName   the desired symmetric algorithm name
    * @param keys          the recipient's public keys (but could include private key part, e.g. for a classical ECDH process)
    * @return              a map defining a string ID and bytes; K (for shared secrets after KDF) or C for ciphertexts.
    */
    Map<String, byte[]> encapsulation(String algorithmSpec, String providerName,  String encAlgoName,
                                                     Map<String, KeyPair> keys);
    
    /**
    * Generates KeyPair(s)
    * @param algorithmSpec the name of the algorithm based on the desired crypto. provider
    * @param providerName  the name of the (BC) provider.
    * @param encAlgoName   the desired symmetric algorithm name
    * @param C    the ciphertext to be decrypted
    * @param keys          the private keys to decapsulate ciphertexts (but could include public key part, e.g. for a classical ECDH process)    
    * @return              the symmetric keying material
    */
    byte[] decapsulation(String algorithmSpec, String providerName, String encAlgoName, byte[] C, Map<String,KeyPair> keys); 
}
