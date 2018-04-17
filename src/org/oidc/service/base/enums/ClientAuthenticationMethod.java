package org.oidc.service.base.enums;

/**
 * Types of ClientAuthenticationMethods
 */
public enum ClientAuthenticationMethod {
    CLIENT_SECRET_BASIC, CLIENT_SECRET_POST,
    BEARER_HEADER, BEARER_BODY,
    CLIENT_SECRET_JWT, PRIVATE_KEY_JWT, NONE;
}
