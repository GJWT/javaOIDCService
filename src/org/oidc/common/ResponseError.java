package org.oidc.common;

public class ResponseError extends Exception{
    public ResponseError(String message) {
        super(message);
    }
}
