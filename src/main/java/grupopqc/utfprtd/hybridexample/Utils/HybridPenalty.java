package grupopqc.utfprtd.hybridexample.Utils;

public class HybridPenalty {
    public String algorithm;
    public double penaltyKeyGen = 0; //e.g., keygen/s hybrid - keygen/s pqc
    public double penaltyEnc = 0;   //encaps or sign
    public double penaltyDec = 0;   //decaps or verify

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }   
    
    public double getPenaltyKeyGen() {
        return penaltyKeyGen;
    }

    public void setPenaltyKeyGen(double penaltyKeyGen) {
        this.penaltyKeyGen = penaltyKeyGen;
    }

    public double getPenaltyEnc() {
        return penaltyEnc;
    }

    public void setPenaltyEnc(double penaltyEnc) {
        this.penaltyEnc = penaltyEnc;
    }

    public double getPenaltyDec() {
        return penaltyDec;
    }

    public void setPenaltyDec(double penaltyDec) {
        this.penaltyDec = penaltyDec;
    }
    
}
