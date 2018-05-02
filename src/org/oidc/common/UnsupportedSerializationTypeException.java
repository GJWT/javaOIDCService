package org.oidc.common;

/**
 * Is thrown when the asked for SerializationType is not supported
 * for serialization or deserialization purposes
 */
public class UnsupportedSerializationTypeException extends Exception{
    public UnsupportedSerializationTypeException(String message) {
        super(message);
    }
}
