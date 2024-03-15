package grupopqc.utfprtd.hybridexample.Algorithms;

import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;

/**
 *
 * Strategy Pattern for the key establishment modes
 */
public interface KeyEstablishmentStrategy {

    KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber768;
    String provaderClassicStrategy = "BC";
    String algorithmClassicStrategy = "ECDH";
    String pqcParameterSpecs = "KYBER768";
    String classicParameterSpec = "P-384";
    String providerName = "BCPQC";

    byte[] ukm = new byte[32];

    /**
     *
     * @param algorithm parameter used to define which encryption algorithm to use with its additional settings
     * @return void
     */
    void setPqcParameterSpecs(String algorithm);

    /**
     *
     * @param providerName specific provader parameter
     */
    void setProviderName(String providerName);
    /**
    * Generates KeyPair(s)
    * @return              the map of keyPair(s) generated. The string part could be defined as "PQC", "Classical" for indexing modes.
     * @return void
     */
    Map<String, KeyPair> keyGeneration();
    /**
    * Performs encapsulation (KEM.Encaps() style)
    * @param encAlgoName   the desired symmetric algorithm name
    * @param keys          the recipient's public keys (but could include private key part, e.g. for a classical ECDH process)
    * @return              a map defining a string ID and bytes; K (for shared secrets after KDF) or C for ciphertexts.
    */
    Map<String, byte[]> encapsulation(String encAlgoName, Map<String, KeyPair> keys);
    
    /**
    * Generates KeyPair(s)
    * @param encAlgoName   the desired symmetric algorithm name
    * @param C    the ciphertext to be decrypted
    * @param keys          the private keys to decapsulate ciphertexts (but could include public key part, e.g. for a classical ECDH process)    
    * @return              the symmetric keying material
    */
    byte[] decapsulation(String encAlgoName, byte[] C, Map<String,KeyPair> keys);
}
