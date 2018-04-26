package org.oidc.common;

/**
 * When the actual value does not match
 * what's expected
 */
public class ValueException extends Exception{
    public ValueException(String message) {
        super(message);
    }
}
