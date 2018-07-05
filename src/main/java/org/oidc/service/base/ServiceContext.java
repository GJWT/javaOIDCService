package org.oidc.service.base;

import com.auth0.msg.Claim;
import com.auth0.msg.DataLocation;
import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Jwk;
import com.auth0.msg.Key;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.ProviderConfigurationResponse;
import com.auth0.msg.RSAKey;
import com.auth0.msg.RegistrationRequest;
import com.auth0.msg.RegistrationResponse;
import com.google.common.base.Strings;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.oidc.common.Algorithm;
import org.oidc.common.FileOrUrl;
import org.oidc.common.KeySpecifications;
import org.oidc.common.ValueException;
import org.oidc.service.util.Constants;

/**
 * This class keeps information that a client needs to be able to talk
 * to a server. Some of this information comes from configuration and some
 * from dynamic provider info discovery or client registration, but information is also
 * picked up during the conversation with a server.
 **/
public class ServiceContext {
    /**
     * Used to store keys
     */
    private KeyJar keyJar = new KeyJar();
    /**
     * Additional configuration arguments
     */
    private ServiceContextConfig config;
    /**
     * Where dynamically received or statically assigned provider
     * information is stored
     */
    private ProviderConfigurationResponse providerConfigurationResponse;
    /**
     * Where the response to a dynamic client registration is stored.
     */
    private RegistrationResponse registrationResponse;
    /**
     * A client will need to dynamically construct a number of URLs, which
     * is the basis for all the URLs.
     */
    private String baseUrl;
    /**
     * Doing Authorization request parts or the whole request can be
     * passed by reference using the requestUri. The request itself
     * must be stored somewhere hence the requestsDirectory.
     */
    private String requestsDirectory;
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
     */
    private Map<String, Boolean> allow;
    /**
     * If manual client registration is done, this is where the results of
     * that is kept.
     * If dynamic client registration is done, this is the result of
     * mapping the registration response against the clientPreferences
     */
    private RegistrationResponse behavior;
    /**
     * If dynamic client registration is done, this is where it’s specified
     * what the client would like to use. This is the basis for the
     * registration request.
     */
    private RegistrationRequest clientPreferences;
    /**
     * The client identifier, which is always required.
     */
    private String clientId;
    /**
     * The client secret, which is optional.
     */
    private String clientSecret;
    /**
     * The Issuer ID. This is the unique identifier of the OP/AS the
     * client is communicating with.
     */
    private String issuer;
    /**
     * An unordered list of redirect uris that the client expects to use.
     */
    private List<String> redirectUris;
    /**
     * redirectUris contains a list of unspecified redirect uris.
     * In reality there are good reasons for having separated redirect
     * uris for different expected response modes.
     * At this time we know of 3 such modes:
     * fragment, queryString, formPost
     * In callback, we can keep the redirect uris per response mode
     * separate.
     */
    private Map<DataLocation, String> callBack;

    /**
     * Constants
     */
    private static final String SIG = "sig";
    private static final String SHA_256 = "SHA-256";
    private static final String ISSUER = "issuer";

    public ServiceContext(
            KeyJar keyJar,
            ServiceContextConfig config) {
        this.keyJar = keyJar;
        this.config = config;
    }

    public ServiceContext() {

    }

    /**
     * The client needs its own set of keys. It can either dynamically create them or load them from local storage. This method can also fetch other entities keys provided that the URL points to a JWKS.
     *
     * @param keySpecifications contains fileName and algorithm
     **/
    public void importKeys(Map<FileOrUrl, KeySpecifications> keySpecifications) {
        if (keySpecifications == null) {
            throw new IllegalArgumentException("null keySpecifications");
        }

        Set<FileOrUrl> keys = keySpecifications.keySet();
        KeySpecifications keySpecificationsIndex;
        Key rsaKey;
        KeyBundle keyBundle;
        Algorithm algorithm;
        for (FileOrUrl key : keys) {
            if (FileOrUrl.FILE.equals(key)) {
                keySpecificationsIndex = keySpecifications.get(key);
                algorithm = keySpecificationsIndex.getAlgorithm();
                if (Algorithm.RS256.equals(algorithm) ||
                        Algorithm.RS384.equals(algorithm)
                        || Algorithm.RS512.equals(algorithm)) {
                    rsaKey = new RSAKey(Jwk.importPrivateRsaKeyFromFile(keySpecificationsIndex.getFileName()), SIG);
                    keyBundle = new KeyBundle();
                    keyBundle.addKey(rsaKey);
                    keyJar.addKeyBundle("", keyBundle);
                }
            } else if (FileOrUrl.URL.equals(key)) {
                keyBundle = new KeyBundle();
                keyJar.addKeyBundle(ISSUER, keyBundle);
            }
        }
    }

    /**
     * A 1<->1 map is maintained between a URL pointing to a file and
     * the name of the file in the file system.
     * <p>
     * As an example if the base_url is 'https://example.com' and a jwks_uri
     * is 'https://example.com/jwks_uri.json' then the filename of the
     * corresponding file on the local filesystem would be 'jwks_uri'.
     * Relative to the directory from which the RP instance is run.
     *
     * @param webName the published URL
     * @return local filename
     **/
    public String fileNameFromWebname(String webName) throws ValueException {
        if (Strings.isNullOrEmpty(webName)) {
            throw new IllegalArgumentException("null or empty webName");
        }

        if (!webName.startsWith(this.baseUrl)) {
            throw new ValueException("Webname does not match baseUrl");
        }

        webName = webName.substring(this.baseUrl.length());
        if (webName.startsWith("/")) {
            return webName.substring(1);
        } else {
            return webName;
        }
    }

    /**
     * Need to generate a redirectUri path that is unique for an OP/RP combo.  This is to counter the mix-up attack.
     *
     * @param requestsDirectory the leading path
     * @return a list of one unique URL
     * @throws InvalidClaimException 
     **/
    public List<String> generateRequestUris(String requestsDirectory) throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
        MessageDigest messageDigest = MessageDigest.getInstance(SHA_256);
        Claim issuerClaim = new Claim(Constants.ISSUER);
        if (this.providerConfigurationResponse.getClaims() != null
                && this.providerConfigurationResponse.getClaims().get(issuerClaim) != null
                && this.providerConfigurationResponse.getClaims().get(issuerClaim) instanceof List
                && !((List) this.providerConfigurationResponse.getClaims().get(issuerClaim)).isEmpty()) {
            for (String issuer : ((List<String>) this.providerConfigurationResponse.getClaims().get(issuerClaim))) {
                messageDigest.update(issuer.getBytes());
            }
        } else {
            if(!Strings.isNullOrEmpty(this.issuer)) {
                messageDigest.digest(this.issuer.getBytes());
            } else {
                throw new ValueException("null or empty issuer");
            }
        }
        messageDigest.digest(this.baseUrl.getBytes());
        if (!requestsDirectory.startsWith("/")) {
            return Arrays.asList(this.baseUrl + "/" + requestsDirectory + "/" + messageDigest.digest());
        } else {
            return Arrays.asList(this.baseUrl + requestsDirectory + "/" + messageDigest.digest());
        }
    }

    public KeyJar getKeyJar() {
        return keyJar;
    }

    public void setKeyJar(KeyJar keyJar) {
        this.keyJar = keyJar;
    }

    public ServiceContextConfig getConfig() {
        return config;
    }

    public void setConfig(ServiceContextConfig config) {
        this.config = config;
    }

    public ProviderConfigurationResponse getProviderConfigurationResponse() {
        return providerConfigurationResponse;
    }

    public void setProviderConfigurationResponse(ProviderConfigurationResponse providerConfigurationResponse) {
        this.providerConfigurationResponse = providerConfigurationResponse;
    }

    public RegistrationResponse getRegistrationResponse() {
        return registrationResponse;
    }

    public void setRegistrationResponse(RegistrationResponse registrationResponse) {
        this.registrationResponse = registrationResponse;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getRequestsDirectory() {
        return requestsDirectory;
    }

    public void setRequestsDirectory(String requestsDirectory) {
        this.requestsDirectory = requestsDirectory;
    }

    public Map<String, Boolean> getAllow() {
        return allow;
    }

    public void setAllow(Map<String, Boolean> allow) {
        this.allow = allow;
    }

    public RegistrationResponse getBehavior() {
        return behavior;
    }

    public void setBehavior(RegistrationResponse behavior) {
        this.behavior = behavior;
    }

    public RegistrationRequest getClientPreferences() {
        return clientPreferences;
    }

    public void setClientPreferences(RegistrationRequest clientPreferences) {
        this.clientPreferences = clientPreferences;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public Map<DataLocation, String> getCallBack() {
        return callBack;
    }

    public void setCallBack(Map<DataLocation, String> callBack) {
        this.callBack = callBack;
    }
}
