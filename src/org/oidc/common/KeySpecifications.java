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
    private String algorithm;

    public KeySpecifications(String fileName, String algorithm) {
        this.fileName = fileName;
        this.algorithm = algorithm;
    }

    public String getFileName() {
        return fileName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}