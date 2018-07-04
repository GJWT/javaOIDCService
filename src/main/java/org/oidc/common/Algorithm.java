package org.oidc.common;

/**
 * All the algorithms that can be used for signing or verifying a token as determined by Auth0
 */
public enum Algorithm {
    /**
     * RS256 algorithm
     **/
    RS256,
    /**
     * RS384 algorithm
     **/
    RS384,
    /**
     * RS512 algorithm
     **/
    RS512,
    /**
     * HS256 algorithm
     **/
    HS256,
    /**
     * HS384 algorithm
     **/
    HS384,
    /**
     * HS512 algorithm
     **/
    HS512,
    /**
     * ES256 algorithm
     **/
    ES256,
    /**
     * ES384 algorithm
     **/
    ES384,
    /**
     * ES512 algorithm
     **/
    ES512;
}