package org.oidc.common;

/**
 * Provides the fileName and algorithm needed for importing keys
 **/
public class KeySpecifications {

    /**
     * Name of the file that contains the keys
     */
    private String fileName;
    /**
     * The algorithm that was used to encrypt the keys
     */
    private Algorithm algorithm;

    public KeySpecifications(String fileName, Algorithm algorithm) {
        this.fileName = fileName;
        this.algorithm = algorithm;
    }

    public String getFileName() {
        return fileName;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }
}