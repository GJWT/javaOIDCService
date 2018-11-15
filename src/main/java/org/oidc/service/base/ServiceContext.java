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
import org.oidc.common.EndpointName;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.msg.oauth2.ASConfigurationResponse;
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
   * Used to store keys
   */
  private KeyJar keyJar;
  /**
   * Where dynamically received or statically assigned provider information is stored
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
   * An unordered list of redirect uris that the client expects to use.
   */
  private List<String> redirectUris;
  /**
   * redirectUris contains a list of unspecified redirect uris. In reality there are good reasons
   * for having separated redirect uris for different expected response modes. At this time we know
   * of 3 such modes: fragment, queryString, formPost In callback, we can keep the redirect uris per
   * response mode separate.
   */
  private Map<String, String> callBack;
  /**
   * URL to which the RP is requesting that the End-User's User Agent be redirected after a logout
   * has been performed.
   */
  private List<String> postLogoutRedirectUris;
  /**
   * Map of service endpoint URLs corresponding to the endpoint name.
   */
  private Map<EndpointName, String> endpoints;

  public ServiceContext(KeyJar keyJar) {
    endpoints = new HashMap<EndpointName, String>();
    this.allow = new HashMap<>();
    this.keyJar = keyJar;
  }

  public ServiceContext() {
    this(null);
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

    /*
     * Commented the code below as it doesn't make sense: issuer in the provider configuration
     * response is always single string and always existing.
     * 
     * Claim issuerClaim = new Claim(Constants.ISSUER); if
     * (this.providerConfigurationResponse.getClaims() != null &&
     * this.providerConfigurationResponse.getClaims().get(issuerClaim) != null &&
     * this.providerConfigurationResponse.getClaims().get(issuerClaim) instanceof List && !((List)
     * this.providerConfigurationResponse.getClaims().get(issuerClaim)).isEmpty()) { for (String
     * issuer : ((List<String>) this.providerConfigurationResponse.getClaims() .get(issuerClaim))) {
     * messageDigest.update(issuer.getBytes()); }
     */
    if (this.providerConfigurationResponse.getClaims() != null
        && this.providerConfigurationResponse.getClaims().get(Constants.ISSUER) != null) {
      messageDigest
          .update(((String) this.providerConfigurationResponse.getClaims().get(Constants.ISSUER))
              .getBytes());
      // This is where the commented code ended
    } else {
      if (!Strings.isNullOrEmpty(this.issuer)) {
        messageDigest.update(this.issuer.getBytes());
      } else {
        throw new ValueException("null or empty issuer");
      }
    }
    messageDigest.update(this.baseUrl.getBytes());
    if (!requestsDirectory.startsWith("/")) {
      return Arrays.asList(this.baseUrl + "/" + requestsDirectory + "/" + messageDigest.digest());
    } else {
      return Arrays.asList(this.baseUrl + requestsDirectory + "/" + messageDigest.digest());
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
   * @param clockSkew  Clock Skew allowed for expiration evaluations
   */
  public void setClockSkew(long clockSkew) {
    this.clockSkew = clockSkew;
  }
  public KeyJar getKeyJar() {
    return keyJar;
  }

  public void setKeyJar(KeyJar keyJar) {
    this.keyJar = keyJar;
  }

  public ASConfigurationResponse getProviderConfigurationResponse() {
    return providerConfigurationResponse;
  }

  public void setProviderConfigurationResponse(
      ASConfigurationResponse providerConfigurationResponse) {
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
  
  public boolean isAllowed(String key) {
    if (allow.containsKey(key)) {
      return allow.get(key);
    }
    return false;
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
  
  public Date getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }
  
  public void setClientSecretExpiresAt(Date expiresAt) {
    this.clientSecretExpiresAt = expiresAt;
  }

  public String getRegistrationAccessToken() {
    return this.registrationAccessToken;
  }
  
  public void setRegistrationAccessToken(String accessToken) {
    this.registrationAccessToken = accessToken;
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

  public Map<String, String> getCallBack() {
    return callBack;
  }

  public void setCallBack(Map<String, String> callBack) {
    this.callBack = callBack;
  }
  
  public List<String> getPostLogoutRedirectUris() {
    return this.postLogoutRedirectUris;
  }

  public void setPostLogoutRedirectUris(List<String> uris) {
    this.postLogoutRedirectUris = uris;
  }
  
  public Map<EndpointName, String> getEndpoints() {
    return this.endpoints;
  }
  
  public void setEndpoints(Map<EndpointName, String> map) {
    this.endpoints = map;
  }
}
