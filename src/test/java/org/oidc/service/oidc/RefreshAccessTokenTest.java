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

package org.oidc.service.oidc;

import com.auth0.msg.KeyJar;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;

/**
 * Unit tests for {@link RefreshAccessToken}.
 */
public class RefreshAccessTokenTest extends BaseServiceTest<RefreshAccessToken> {

  ServiceContext serviceContext;
  String issuer = "https://www.example.com";
  State state;
  String stateKey;

  String endpoint = "https://www.example.com/token";
  String callback = "https://example.com/cb";
  String clientId = "clientid_x";

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    state = new InMemoryStateImpl();
    stateKey = state.createStateRecord(issuer, null);
    service = new RefreshAccessToken(serviceContext, state, null);
    service.setEndpoint(endpoint);
    List<String> redirectUris = new ArrayList<String>();
    redirectUris.add(callback);
    serviceContext.setRedirectUris(redirectUris);
    serviceContext.setIssuer(issuer);
    serviceContext.setKeyJar(new KeyJar());
    serviceContext.setClientId(clientId);
    serviceContext.setClockSkew(10);
    serviceContext.setBehavior(new RegistrationResponse());
    serviceContext.getBehavior().getClaims().put("id_token_signed_response_alg", "RS256");
    serviceContext.getBehavior().getClaims().put("id_token_encrypted_response_alg", "RSA1_5");
    serviceContext.getBehavior().getClaims().put("id_token_encrypted_response_enc", "A128GCM");
    serviceContext.getBehavior().getClaims().put("token_endpoint_auth_method", "bearer_body");
    serviceContext.getAllow().put("missing_kid", true);

    AccessTokenResponse resp = new AccessTokenResponse();
    resp.addClaim("refresh_token", "refreshtoken");
    state.storeItem(resp, stateKey, MessageType.TOKEN_RESPONSE);
    Map<String, Object> preConstructorArgs = new HashMap<String, Object>();
    preConstructorArgs.put("state", stateKey);
    service.setPreConstructorArgs(preConstructorArgs);
  }

  @Test
  public void testHttpGetParametersMinimal() throws Exception {
    HttpArguments httpArguments = service.getRequestParameters(null);
    Assert.assertEquals(HttpMethod.POST, httpArguments.getHttpMethod());
    Assert.assertTrue(httpArguments.getUrl().startsWith(endpoint));
    Assert.assertTrue(httpArguments.getBody().contains("refresh_token=refreshtoken"));
    Assert.assertTrue(httpArguments.getBody().contains("grant_type=refresh_token"));
  }

  @Test
  public void testdoUpdateServiceContextResponseStored()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    AccessTokenResponse response = new AccessTokenResponse();
    response.addClaim("token_type", "bearer");
    response.addClaim("access_token", "value");
    service.updateServiceContext(response, stateKey);
    Message storedResponse = state.getItem(stateKey, MessageType.REFRESH_TOKEN_RESPONSE);
    Assert.assertTrue(storedResponse instanceof AccessTokenResponse);
    Assert.assertEquals("value", response.getClaims().get("access_token"));
  }

  private IDToken getIDToken() {
    Date now = new Date();
    IDToken idToken = new IDToken();
    idToken.addClaim("iss", issuer);
    idToken.addClaim("sub", "user01");
    idToken.addClaim("aud", clientId);
    idToken.addClaim("exp", new Date(now.getTime() + 1000));
    idToken.addClaim("iat", now);
    idToken.addClaim("nonce", "noncevalue");
    return idToken;
  }

  @Test
  public void testdoUpdateServiceContextIdTokenStored() throws MissingRequiredAttributeException,
      ValueException, InvalidClaimException, SerializationException {
    // We have to create a id token that passes the tests
    AccessTokenResponse response = new AccessTokenResponse();
    response.addClaim("token_type", "bearer");
    response.addClaim("access_token", "value");
    response.setSigAlg("none");
    response.setClientId(clientId);
    response.addClaim("id_token",
        getIDToken().toJwt(null, "none", null, null, null, null, null, null));
    state.storeStateKeyForNonce("noncevalue", stateKey);
    service.updateServiceContext(response, stateKey);
    Message storedIDToken = state.getItem(stateKey, MessageType.VERIFIED_IDTOKEN);
    Message storedResponse = state.getItem(stateKey, MessageType.REFRESH_TOKEN_RESPONSE);
    Assert.assertNotNull(((AccessTokenResponse) storedResponse).getVerifiedIdToken());
    Assert.assertTrue(storedIDToken instanceof IDToken);
    Assert.assertEquals("noncevalue", storedIDToken.getClaims().get("nonce"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testdoUpdateServiceContextIdTokenStoredNonceFail()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException,
      SerializationException {
    // We have to create a id token that passes the tests
    AccessTokenResponse response = new AccessTokenResponse();
    response.addClaim("token_type", "bearer");
    response.addClaim("access_token", "value");
    response.setSigAlg("none");
    response.setClientId(clientId);
    response.addClaim("id_token",
        getIDToken().toJwt(null, "none", null, null, null, null, null, null));
    state.storeStateKeyForNonce("noncevalueWrong", stateKey);
    service.updateServiceContext(response, stateKey);
    Message storedIDToken = state.getItem(stateKey, MessageType.VERIFIED_IDTOKEN);
    Message storedResponse = state.getItem(stateKey, MessageType.REFRESH_TOKEN_RESPONSE);
    Assert.assertNotNull(((AccessTokenResponse) storedResponse).getVerifiedIdToken());
    Assert.assertTrue(storedIDToken instanceof IDToken);
    Assert.assertEquals("noncevalue", storedIDToken.getClaims().get("nonce"));
  }

  @Test
  public void testdoUpdateServiceContextExpiresAt()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    AccessTokenResponse response = new AccessTokenResponse();
    response.addClaim("token_type", "bearer");
    response.addClaim("access_token", "value");
    long expires = 3600;
    response.addClaim("expires_in", expires);
    service.updateServiceContext(response, stateKey);
    Message storedResponse = state.getItem(stateKey, MessageType.REFRESH_TOKEN_RESPONSE);
    Assert.assertTrue(storedResponse instanceof AccessTokenResponse);
    Assert.assertTrue(storedResponse.getClaims().containsKey("__expires_at"));
  }

  @Test
  public void testprepareMessageForVerification() {
    AccessTokenResponse response = new AccessTokenResponse();
    service.prepareMessageForVerification(response);
    // There is no simple way to test parameters are set except cobertura report
  }

  @Test
  public void testprepareMessageForVerificationNullInput() {
    AccessTokenResponse response = new AccessTokenResponse();
    serviceContext.setBehavior(null);
    serviceContext.getAllow().put("missing_kid", null);
    service.prepareMessageForVerification(response);
    // There is no simple way to test parameters are set except cobertura report
  }

  @Test
  public void testgetDefaultAuthenticationMethodNoInput() {
    serviceContext.getBehavior().getClaims().remove("token_endpoint_auth_method");
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        service.getDefaultAuthenticationMethod());
  }

  @Test
  public void testgetDefaultAuthenticationMethodPreferredSet() {
    Assert.assertEquals(ClientAuthenticationMethod.BEARER_BODY,
        service.getDefaultAuthenticationMethod());
  }

  @Test
  public void testgetDefaultAuthenticationMethodNullInput() {
    serviceContext.getBehavior().getClaims().put("token_endpoint_auth_method", null);
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        service.getDefaultAuthenticationMethod());
  }

}
