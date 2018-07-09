package org.oidc.common;

public class MissingRequiredAttributeException extends Exception {
  public MissingRequiredAttributeException(String message) {
    super(message);
  }
}
