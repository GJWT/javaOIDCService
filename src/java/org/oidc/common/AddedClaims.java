package org.oidc.common;

import com.auth0.msg.KeyJar;
import org.oidc.service.data.State;

/**
 * Commonly used claims.
 * May need to be extended to accommodate additional claims
 */
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
    /**
     * Resource
     */
    private String resource;
    /**
     * Client authentication method - defined in enum ClientAuthenticationMethod
     * (The client authentication method to use if nothing else is specified.
     * Default is '' which means none.)
     */
    private ClientAuthenticationMethod clientAuthenticationMethod;
    /**
     * Serves as an in-memory cache
     */
    private State state;

    private AddedClaims(String clientId, String issuer, KeyJar keyJar, boolean shouldVerify,
                        String scope, String resource, ClientAuthenticationMethod clientAuthenticationMethod,
                        State state) {
        this.clientId = clientId;
        this.issuer = issuer;
        this.keyJar = keyJar;
        this.shouldVerify = shouldVerify;
        this.scope = scope;
        this.resource = resource;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.state = state;
    }

    /**
     * Constructor used to copy an AddedClaims object
     * to another
     * @param addedClaims
     */
    private AddedClaims(AddedClaims addedClaims) {
        this.clientId = addedClaims.clientId;
        this.issuer = addedClaims.issuer;
        this.keyJar = addedClaims.keyJar;
        this.shouldVerify = addedClaims.shouldVerify;
        this.scope = addedClaims.scope;
        this.resource = addedClaims.resource;
        this.clientAuthenticationMethod = addedClaims.clientAuthenticationMethod;
        this.state = addedClaims.state;
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

    public String getResource() { return resource; }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public State getState() {
        return state;
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
        private String resource;
        private ClientAuthenticationMethod clientAuthenticationMethod;
        private State state;

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

        public AddedClaimsBuilder setScope(String scope) {
            this.scope = scope;
            return this;
        }

        public AddedClaimsBuilder setResource(String resource) {
            this.resource = resource;
            return this;
        }

        public AddedClaimsBuilder setClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethod = clientAuthenticationMethod;
            return this;
        }

        public AddedClaimsBuilder setState(State state) {
            this.state = state;
            return this;
        }

        public AddedClaims setAddedClaims(AddedClaims addedClaims) {
            return new AddedClaims(addedClaims);
        }

        public AddedClaims buildAddedClaims() {
            return new AddedClaims(clientId, issuer, keyJar, shouldVerify, scope, resource, clientAuthenticationMethod, state);
        }
    }
}

