package org.oidc.common;

/**
 * Base exception that all OIDC service exceptions extend from
 */
public class OidcServiceException extends Exception {
  public OidcServiceException(String message) {
    super(message);
  }
}
