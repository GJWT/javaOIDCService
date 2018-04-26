package org.oidc.common;

/**
 * Is thrown for example when a response is null after
 * calling postParseResponse()
 */
public class ResponseException extends Exception{
    public ResponseException(String message) {
        super(message);
    }
}
