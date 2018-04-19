package org.oidc.common;

/**
 * Provides the fileName and algorithm needed for importing keys
 **/
public class KeySpecifications {

    private String fileName;
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
}