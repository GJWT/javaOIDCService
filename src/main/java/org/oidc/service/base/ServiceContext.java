/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.service.base;

import com.auth0.msg.KeyJar;
import com.google.common.base.Strings;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.oidc.common.EndpointName;
import org.oidc.common.ValueException;
import org.oidc.msg.DataLocation;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.util.Constants;

/**
 * This class keeps information that a client needs to be able to talk to a server. Some of this
 * information comes from configuration and some from dynamic provider info discovery or client
 * registration, but information is also picked up during the conversation with a server.
 **/
public class ServiceContext {

  /** Clock Skew allowed for expiration evaluations. */
  private long clockSkew = 0;

  /**
   * Storage for the keys.
   */
  private KeyJar keyJar;

  /**
   * Where dynamically received or statically assigned provider information is stored.
   */
  private ASConfigurationResponse providerConfigurationResponse;

  /**
   * Where the response to a dynamic client registration is stored.
   */
  private RegistrationResponse registrationResponse;

  /**
   * A client will need to dynamically construct a number of URLs, which is the basis for all the
   * URLs.
   */
  private String baseUrl;

  /**
   * Doing Authorization request parts or the whole request can be passed by reference using the
   * requestUri. The request itself must be stored somewhere hence the requestsDirectory.
   */
  private String requestsDirectory;

  /**
   * Divergence from the standard can be more or less severe. Less severe cases can be allowed but
   * only if it’s deemed OK. The only example of this right now is issuer mismatch. As an example:
   * According to the OpenID Connect standard the ‘issuer’ returned in dynamic discovery must be the
   * same as the value of the ‘iss’ parameter in the Id Token and the discovery URL that was used
   * without the .well-known part. See for instance
   * http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation Some OP implementations
   * doesn’t live up to this. And that by design. So, if you want to talk to those you have to allow
   * them to diverge from the standard.
   */
  private Map<String, Boolean> allow;

  /**
   * If manual client registration is done, this is where the results of that is kept. If dynamic
   * client registration is done, this is the result of mapping the registration response against
   * the clientPreferences
   */
  private RegistrationResponse behavior;

  /**
   * If dynamic client registration is done, this is where it’s specified what the client would like
   * to use. This is the basis for the registration request.
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
   * The client secret expiration time, which is optional.
   */
  private Date clientSecretExpiresAt;

  /**
   * The registration access token, which is optional.
   */
  private String registrationAccessToken;

  /**
   * The Issuer ID. This is the unique identifier of the OP/AS the client is communicating with.
   */
  private String issuer;

  /**
   * An unordered list of redirect URIs that the client expects to use.
   */
  private List<String> redirectUris;

  /**
   * redirectUris contains a list of unspecified redirect URIs. In reality there are good reasons
   * for having separated redirect URIs for different expected response modes. At this time we know
   * of 3 such modes: fragment, queryString, formPost In callback, we can keep the redirect URIs per
   * response mode separate.
   */
  private Map<DataLocation, String> callBack;

  /**
   * URL to which the RP is requesting that the End-User's User Agent be redirected after a logout
   * has been performed.
   */
  private List<String> postLogoutRedirectUris;

  /**
   * Map of service endpoint URLs corresponding to the endpoint name.
   */
  private Map<EndpointName, String> endpoints;

  /**
   * The URL containing the public key information of this RP.
   */
  private String jwksUri;

  /**
   * Constructor.
   * 
   * @param keyJar
   *          KeyJar to store keys to.
   */
  public ServiceContext(KeyJar keyJar) {
    endpoints = new HashMap<EndpointName, String>();
    allow = new HashMap<>();
    this.keyJar = keyJar;
    requestsDirectory = "requests";
  }

  /**
   * Constructor.
   */
  public ServiceContext() {
    this(new KeyJar());
  }

  /**
   * Need to generate a redirectUri path that is unique for an OP/RP combo. This is to counter the
   * mix-up attack.
   *
   * @param requestsDirectory
   *          the leading path
   * @return a list of one unique URL
   * @throws InvalidClaimException
   **/
  public List<String> generateRequestUris(String requestsDirectory)
      throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

    if (providerConfigurationResponse.getClaims() != null
        && providerConfigurationResponse.getClaims().get(Constants.ISSUER) != null) {
      messageDigest.update(
          ((String) providerConfigurationResponse.getClaims().get(Constants.ISSUER)).getBytes());
    } else {
      if (!Strings.isNullOrEmpty(issuer)) {
        messageDigest.update(issuer.getBytes());
      } else {
        throw new ValueException("Issuer could not be resolved");
      }
    }
    messageDigest.update(baseUrl.getBytes());
    String digest = Base64.encodeBase64URLSafeString(messageDigest.digest());
    if (!requestsDirectory.startsWith("/")) {
      return Arrays.asList(baseUrl + "/" + requestsDirectory + "/" + digest);
    } else {
      return Arrays.asList(baseUrl + requestsDirectory + "/" + digest);
    }
  }

  /**
   * Get Clock Skew allowed for expiration evaluations.
   * 
   * @return Clock Skew allowed for expiration evaluations
   */
  public long getClockSkew() {
    return clockSkew;
  }

  /**
   * Set Clock Skew allowed for expiration evaluations.
   * 
   * @param clockSkew
   *          Clock Skew allowed for expiration evaluations
   */
  public void setClockSkew(long clockSkew) {
    this.clockSkew = clockSkew;
  }

  /**
   * Get storage for the keys.
   * 
   * @return storage for the keys.
   */
  public KeyJar getKeyJar() {
    return keyJar;
  }

  /**
   * Set storage for the keys.
   * 
   * @param keyJar
   *          storage for the keys
   */
  public void setKeyJar(KeyJar keyJar) {
    this.keyJar = keyJar;
  }

  /**
   * Get provider information. May be dynamically received or statically assigned.
   * 
   * @return provider information
   */
  public ASConfigurationResponse getProviderConfigurationResponse() {
    return providerConfigurationResponse;
  }

  /**
   * Set provider information. May be dynamically received or statically assigned.
   * 
   * @param providerConfigurationResponse
   *          provider information
   */
  public void setProviderConfigurationResponse(
      ASConfigurationResponse providerConfigurationResponse) {
    this.providerConfigurationResponse = providerConfigurationResponse;
  }

  /**
   * Get dynamic client registration response.
   * 
   * @return dynamic client registration response
   */
  public RegistrationResponse getRegistrationResponse() {
    return registrationResponse;
  }

  /**
   * Set dynamic client registration response.
   * 
   * @param registrationResponse
   *          dynamic client registration response
   */
  public void setRegistrationResponse(RegistrationResponse registrationResponse) {
    this.registrationResponse = registrationResponse;
  }

  /**
   * Get the basis for all dynamically constructed URLs.
   * 
   * @return basis for all dynamically constructed URLs
   */
  public String getBaseUrl() {
    return baseUrl;
  }

  /**
   * Set the basis for all dynamically constructed URLs.
   * 
   * @param baseUrl
   *          basis for all dynamically constructed URLs
   */
  public void setBaseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
  }

  /**
   * Get directory for storing request object. This is required when request object is passed by
   * reference and we need to store the request object.
   * 
   * @return directory for storing request object
   */
  public String getRequestsDirectory() {
    return requestsDirectory;
  }

  /**
   * Set directory for storing request object. This is required when request object is passed by
   * reference and we need to store the request object.
   * 
   * @param requestsDirectory
   *          directory for storing request object
   */
  public void setRequestsDirectory(String requestsDirectory) {
    this.requestsDirectory = requestsDirectory;
  }

  /**
   * Get divergence map. Divergence from the standard can be more or less severe. Less severe cases
   * can be allowed but only if it’s deemed OK. The only examples of this right now are issuer
   * mismatch ('issuer_mismatch') and missing kid ('missing_kid'). As an example: According to the
   * OpenID Connect standard the ‘issuer’ returned in dynamic discovery must be the same as the
   * value of the ‘iss’ parameter in the Id Token and the discovery URL that was used without the
   * .well-known part. See for instance
   * http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation Some OP implementations
   * doesn’t live up to this. And that by design. So, if you want to talk to those you have to allow
   * them to diverge from the standard.
   *
   * @return divergence map
   */
  public Map<String, Boolean> getAllow() {
    return allow;
  }

  /**
   * Set divergence map. Divergence from the standard can be more or less severe. Less severe cases
   * can be allowed but only if it’s deemed OK. The only examples of this right now are issuer
   * mismatch ('issuer_mismatch') and missing kid ('missing_kid'). As an example: According to the
   * OpenID Connect standard the ‘issuer’ returned in dynamic discovery must be the same as the
   * value of the ‘iss’ parameter in the Id Token and the discovery URL that was used without the
   * .well-known part. See for instance
   * http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation Some OP implementations
   * doesn’t live up to this. And that by design. So, if you want to talk to those you have to allow
   * them to diverge from the standard.
   * 
   * @param allow
   *          divergence map
   */
  public void setAllow(Map<String, Boolean> allow) {
    this.allow = allow;
  }

  /**
   * Whether divergence map contains value true for the given key.
   * 
   * @param key
   *          to test. Either 'issuer_mismatch' or 'missing_kid'.
   * @return true if divergence map contains value true for the given key. Other wise false.
   */
  public boolean isAllowed(String key) {
    if (allow.containsKey(key)) {
      return allow.get(key);
    }
    return false;
  }

  /**
   * Get the RP behavior. If manual client registration is done, this is where the results of that
   * is kept. If dynamic client registration is done, this is the result of mapping the registration
   * response against the clientPreferences.
   * 
   * @return RP behavior.
   */
  public RegistrationResponse getBehavior() {
    return behavior;
  }

  /**
   * Set the RP behavior. If manual client registration is done, use this method to set the
   * configuration. If dynamic client registration is done by Registration service this method need
   * not to be used.
   * 
   * @param behavior
   *          RP behavior.
   */
  public void setBehavior(RegistrationResponse behavior) {
    this.behavior = behavior;
  }

  /**
   * Get client preferences. If dynamic client registration is done, this is where it’s specified
   * what the client would like to use. This is the basis for the registration request.
   * 
   * @return client preferences.
   */
  public RegistrationRequest getClientPreferences() {
    return clientPreferences;
  }

  /**
   * Set client preferences. If dynamic client registration is done, this is where it’s specified
   * what the client would like to use. This is the basis for the registration request.
   * 
   * @param clientPreferences
   *          client preferences
   */
  public void setClientPreferences(RegistrationRequest clientPreferences) {
    this.clientPreferences = clientPreferences;
  }

  /**
   * Get the client identifier.
   * 
   * @return client identifier.
   */
  public String getClientId() {
    return clientId;
  }

  /**
   * Set the client identifier.
   * 
   * @param clientId
   *          client identifier.
   */
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   * Get the client secret.
   * 
   * @return client secret
   */
  public String getClientSecret() {
    return clientSecret;
  }

  /**
   * Set the client secret.
   * 
   * @param clientSecret
   *          client secret
   */
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  /**
   * Get the client secret expiration time.
   * 
   * @return client secret expiration time
   */
  public Date getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }

  /**
   * Set the client secret expiration time.
   * 
   * @param expiresAt
   *          client secret expiration time
   */
  public void setClientSecretExpiresAt(Date expiresAt) {
    clientSecretExpiresAt = expiresAt;
  }

  /**
   * Get the registration access token.
   * 
   * @return registration access token
   */
  public String getRegistrationAccessToken() {
    return registrationAccessToken;
  }

  /**
   * Set the registration access token.
   * 
   * @param accessToken
   *          registration access token
   */
  public void setRegistrationAccessToken(String accessToken) {
    registrationAccessToken = accessToken;
  }

  /**
   * Get the Issuer ID. This is the unique identifier of the OP/AS the client is communicating with.
   * 
   * @return Issuer ID
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * Set the Issuer ID. This is the unique identifier of the OP/AS the client is communicating with.
   * 
   * @param issuer
   *          Issuer ID
   */
  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  /**
   * Get unordered list of redirect URIs that the client expects to use.
   * 
   * @return redirect URIs
   */
  public List<String> getRedirectUris() {
    return redirectUris;
  }

  /**
   * Set unordered list of redirect URIs that the client expects to use.
   * 
   * @param redirectUris
   *          redirect URIs
   */
  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  /**
   * Get map of redirect URIs per response mode. In reality there are good reasons for having
   * separated redirect URIs for different expected response modes. At this time we know of 3 such
   * modes: fragment (key is 'implicit'), queryString (key is 'code'), formPost (key is 'form_post')
   * In callback, we can keep the redirect URIs per response mode separate.
   * 
   * @return map containing redirect URI per response mode
   */
  public Map<DataLocation, String> getCallBack() {
    return callBack;
  }

  /**
   * Set map of redirect URIs per response mode. In reality there are good reasons for having
   * separated redirect URIs for different expected response modes. At this time we know of 3 such
   * modes: fragment (key is 'implicit'), queryString (key is 'code'), formPost (key is 'form_post')
   * In callback, we can keep the redirect URIs per response mode separate.
   * 
   * @param callBack
   *          map containing redirect URI per response mode
   */
  public void setCallBack(Map<DataLocation, String> callBack) {
    this.callBack = callBack;
  }

  /**
   * Get URLs to which the RP is requesting that the End-User's User Agent be redirected after a
   * logout has been performed.
   *
   * @return redirect URIs
   */
  public List<String> getPostLogoutRedirectUris() {
    return postLogoutRedirectUris;
  }

  /**
   * Set URLs to which the RP is requesting that the End-User's User Agent be redirected after a
   * logout has been performed.
   * 
   * @param uris
   *          redirect URIs
   */
  public void setPostLogoutRedirectUris(List<String> uris) {
    postLogoutRedirectUris = uris;
  }

  /**
   * Get map of service endpoint URLs corresponding to the endpoint name.
   * 
   * @return map of service endpoint URLs
   */
  public Map<EndpointName, String> getEndpoints() {
    return endpoints;
  }

  /**
   * Set map of service endpoint URLs corresponding to the endpoint name.
   * 
   * @param map
   *          of service endpoint URLs
   */
  public void setEndpoints(Map<EndpointName, String> map) {
    endpoints = map;
  }

  /**
   * Set the URL containing the public key information of this RP.
   * 
   * @return json web key URI
   */
  public String getJwksUri() {
    return jwksUri;
  }

  /**
   * Get the URL containing the public key information of this RP.
   * 
   * @param uri
   *          json web key URI
   */
  public void setJwksUri(String uri) {
    jwksUri = uri;
  }
}
