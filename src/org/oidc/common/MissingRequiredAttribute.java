package org.oidc.common;

public class MissingRequiredAttribute extends Exception {
    public MissingRequiredAttribute(String message) {
        super(message);
    }
}
