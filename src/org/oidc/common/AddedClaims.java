package org.oidc.common;

import com.auth0.msg.KeyJar;

public class AddedClaims {

    /**
     * The client identifier, which is always required.
     */
    private String clientId;
    /**
     * The Issuer ID. This is the unique identifier of the OP/AS the
     * client is communicating with.
     */
    private String issuer;
    /**
     * Used to store keys
     */
    private KeyJar keyJar;
    /**
     * Whether response should be verified or not
     */
    private boolean shouldVerify;
    /**
     * https://tools.ietf.org/html/rfc6749#section-3.3
     */
    private String scope;

    private AddedClaims(String clientId, String issuer, KeyJar keyJar, boolean shouldVerify, String scope) {
        this.clientId = clientId;
        this.issuer = issuer;
        this.keyJar = keyJar;
        this.shouldVerify = shouldVerify;
        this.scope = scope;
    }

    private AddedClaims(AddedClaims addedClaims) {
        this.clientId = addedClaims.clientId;
        this.issuer = addedClaims.issuer;
        this.keyJar = addedClaims.keyJar;
        this.shouldVerify = addedClaims.shouldVerify;
        this.scope = addedClaims.scope;
    }

    public String getClientId() {
        return clientId;
    }

    public String getIssuer() {
        return issuer;
    }

    public KeyJar getKeyJar() {
        return keyJar;
    }

    public boolean isShouldVerify() {
        return shouldVerify;
    }

    public String getScope() {
        return scope;
    }

    public AddedClaimsBuilder buildAddedClaimsBuilder() {
        return new AddedClaimsBuilder();
    }

    public static class AddedClaimsBuilder {
        private String clientId;
        private String issuer;
        private KeyJar keyJar;
        private boolean shouldVerify;
        private String scope;

        public AddedClaimsBuilder setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public AddedClaimsBuilder setIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public AddedClaimsBuilder setKeyJar(KeyJar keyJar) {
            this.keyJar = keyJar;
            return this;
        }

        public AddedClaimsBuilder setShouldVerify(boolean shouldVerify) {
            this.shouldVerify = shouldVerify;
            return this;
        }

        public AddedClaims setAddedClaims(AddedClaims addedClaims) {
            return new AddedClaims(addedClaims);
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public AddedClaims buildAddedClaims() {
            return new AddedClaims(clientId, issuer, keyJar, shouldVerify, scope);
        }
    }
}

