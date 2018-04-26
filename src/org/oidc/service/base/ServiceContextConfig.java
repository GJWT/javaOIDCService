/*
package org.oidc.service.base;

import java.util.List;
import java.util.Map;
import org.oidc.common.FileOrUrl;
import org.oidc.common.KeySpecifications;
import org.oidc.common.KeyType;
import org.oidc.message.ProviderConfigurationResponse;
import org.oidc.message.RegistrationRequest;
import org.oidc.message.RegistrationResponse;

*/
/**
 * This is the configuration that is created by the configuration of the RP
 * and is shared by all the services because there is one ServiceContext
 * that is instantiated based off this instance
 *//*

public class ServiceContextConfig {

    */
/**
     * Where dynamically received or statically assigned provider
     * information is stored
     *//*

    private ProviderConfigurationResponse providerConfigurationResponse;
    */
/**
     * Where the response to a dynamic client registration is stored.
     * This is the unmodified registration response as received from the
     * authorization server.
     *//*

    private RegistrationResponse registrationResponse;
    */
/**
     * A client will need to dynamically construct a number of URLs, which
     * is the basis for all the URLs.
     *//*

    private String baseUrl;
    */
/**
     * Doing Authorization request parts or the whole request can be
     * passed by reference using the requestUri. The request itself
     * must be stored somewhere hence the requestsDirectory.
     *//*

    private String requestsDirectory;
    */
/**
     * Divergence from the standard can be more or less severe.
     * Less severe cases can be allowed but only if it’s deemed OK.
     * The only example of this right now is issuer mismatch.
     * As an example:
     * According to the OpenID Connect standard the ‘issuer’ returned
     * in dynamic discovery must be the same as the value of the ‘iss’
     * parameter in the Id Token and the discovery URL that was used
     * without the .well-known part.
     * See for instance http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     * Some OP implementations doesn’t live up to this.
     * And that by design. So, if you want to talk to those you have to
     * allow them to diverge from the standard.
     *//*

    private Map<String,String> allow;
    */
/**
     * If manual client registration is done, this is where the results of
     * that is kept.
     * If dynamic client registration is done, this is the result of
     * mapping the registration response against the clientPreferences
     *//*

    private RegistrationResponse behavior;
    */
/**
     * If dynamic client registration is done, this is where it’s
     * specified what the client would like to use.
     * This is the basis for the registration request.
     *//*

    private RegistrationRequest registrationRequest;

    */
/**
     * The client identifier, which is always required.
     *//*

    private String clientId;
    */
/**
     * The client secret, which is optional.
     *//*

    private String clientSecret;
    */
/**
     * The Issuer ID. This is the unique identifier of the OP/AS the
     * client is communicating with.
     *//*

    private String issuer;
    */
/**
     * An unordered list of redirect uris that the client expects to use.
     *//*

    private List<String> redirectUris;
    */
/**
     * redirectUris contains a list of unspecified redirect uris.
     * In reality there are good reasons for having separated redirect
     * uris for different expected response modes.
     * At this time we know of 3 such modes:
     * fragment, queryString, formPost
     * In callback, we can keep the redirect uris per response mode
     * separate.
     *//*

    private Map<String,String> callBack;
    */
/**
     * Some key material may be available to the client at initialization.
     * This can either be from local storage (files) or from a web
     * service.
     * If it’s on the web then the keySpecification will be a
     * MAP<string,string> where the key is the owner of the keys and the
     * value is the URL where the keys can be found. It is assumed that
     * what is received when doing a HTTP GET on the url is a JWKS.
     * If it’s local the keySpecification will be a MAP<string,string>
     * where the key is the owner of the keys and the value is the path
     * to a file containing a JWKS with the key definitions.
     *//*

    private Map<FileOrUrl,KeySpecifications> keys;
    */
/**
     * A specification to be used when dynamically creating a set of keys
     * at startup or when doing key rotation.
     * buildSpecification is a MAP<string, List<string>>
     * if the keyDefs key is EC then the buildSpecification keys are:
     *  ‘crv’ which elliptic curve that should be used, single valued
     *  ‘use’ what the key can be used for; signing and/or encryption
     * if the keyDefs key is RSA then the buildSpecification keys are:
     *  ‘use’ what the key can be used for; signing and/or encryption
     *  ‘name’ The name of the file where the key will be stored
     *  ‘path’ A path to the directory
     *  ‘size’ The key size (1024, 2048, 4096, ..)
     *//*

    private Map<KeyType, buildSpecification> keyDefs;

    public ServiceContextConfig(
            ProviderConfigurationResponse providerConfigurationResponse,
            RegistrationResponse registrationResponse,
            String baseUrl,
            String requestsDirectory,
            Map<String,String> allow,
            RegistrationResponse behavior,
            RegistrationRequest registrationRequest,
            String clientId,
            String clientSecret,
            String issuer,
            List<String> redirectUris,
            Map<String,String> callBack,
            Map<FileOrUrl,KeySpecifications> keys) {
        this.providerConfigurationResponse = providerConfigurationResponse;
        this.registrationResponse = registrationResponse;
        this.baseUrl = baseUrl;
        this.requestsDirectory = requestsDirectory;
        this.allow = allow;
        this.behavior = behavior;
        this.registrationRequest = registrationRequest;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.issuer = issuer;
        this.redirectUris = redirectUris;
        this.callBack = callBack;
        this.keys = keys;
        this.keyDefs = keyDefs;
    }

    public ProviderConfigurationResponse getProviderConfigurationResponse() {
        return providerConfigurationResponse;
    }

    public RegistrationResponse getRegistrationResponse() {
        return registrationResponse;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getRequestsDirectory() {
        return requestsDirectory;
    }

    public Map<String,String> getAllow() {
        return allow;
    }

    public RegistrationResponse getBehavior() {
        return behavior;
    }

    public RegistrationRequest getRegistrationRequest() {
        return registrationRequest;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getIssuer() {
        return issuer;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public Map<String, String> getCallBack() {
        return callBack;
    }

    public Map<FileOrUrl, KeySpecifications> getKeys() {
        return keys;
    }

    public static class ServiceContextConfigBuilder {
        private ProviderConfigurationResponse providerConfigurationResponse;
        private RegistrationResponse registrationResponse;
        private String baseUrl;
        private String requestsDirectory;
        private Map<String,String> allow;
        private RegistrationResponse behavior;
        private RegistrationRequest registrationRequest;
        private String clientId;
        private String clientSecret;
        private String issuer;
        private List<String> redirectUris;
        private Map<String,String> callBack;
        private Map<FileOrUrl,KeySpecifications> keys;

        public ServiceContextConfig.ServiceContextConfigBuilder setProviderInfo(ProviderConfigurationResponse providerConfigurationResponse) {
            this.providerConfigurationResponse = providerConfigurationResponse;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setBehavior(RegistrationResponse behavior) {
            this.behavior = behavior;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setRequestsDirectory(String requestsDirectory) {
            this.requestsDirectory = requestsDirectory;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setAllow(Map<String, String> allow) {
            this.allow = allow;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setBehavior(RegistrationResponse behavior) {
            this.behavior = behavior;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setRegistrationRequest(RegistrationRequest registrationRequest) {
            this.registrationRequest = registrationRequest;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setCallBack(Map<String, String> callBack) {
            this.callBack = callBack;
            return this;
        }

        public ServiceContextConfig.ServiceContextConfigBuilder setKeys(Map<FileOrUrl, KeySpecifications> keys) {
            this.keys = keys;
            return this;
        }

        public ServiceContextConfig buildServiceContext() throws NoSuchFieldException, IllegalAccessException {
            return new ServiceContextConfig(
                    providerConfigurationResponse,
                    registrationResponse,
                    baseUrl,
                    requestsDirectory,
                    allow,
                    behavior,
                    registrationRequest,
                    clientId,
                    clientSecret,
                    issuer,
                    redirectUris,
                    callBack,
                    keys
            );
        }
    }
}
*/
