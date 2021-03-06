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

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;

import com.auth0.msg.KeyJar;

/**
 * Unit tests for {@link Authentication}.
 */
public class AuthenticationTest extends BaseServiceTest<Authentication> {

  ServiceContext serviceContext;
  String issuer = "https://www.example.com";
  Map<String, Object> map = new HashMap<String, Object>();
  State state;
  String stateKey;

  String endpoint = "https://www.example.com/authorize";
  String callback = "https://example.com/cb";
  String responseType = "code";
  String scope = "openid";
  String clientId = "clientid_x";

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    state = new InMemoryStateImpl();
    stateKey = state.createStateRecord(issuer, null);
    service = new Authentication(serviceContext, state, null);
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
    serviceContext.getAllow().put("missing_kid", true);
    map.clear();
    map.put("response_type", responseType);
    map.put("scope", scope);
    map.put("client_id", clientId);
  }

  @Test
  public void testHttpGetParametersMinimal() throws Exception {
    HttpArguments httpArguments = service.getRequestParameters(map);
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
    Assert.assertTrue(httpArguments.getUrl().startsWith(endpoint));
    Assert.assertTrue(httpArguments.getUrl().contains("client_id=" + clientId));
    Assert.assertTrue(httpArguments.getUrl().contains("scope=" + scope));
    Assert.assertTrue(httpArguments.getUrl().contains("response_type=" + responseType));
    Assert.assertTrue(
        httpArguments.getUrl().contains("redirect_uri=" + URLEncoder.encode(callback, "UTF-8")));
    String stateKey = (String) service.getRequestMessage().getClaims().get("state");
    AuthenticationRequest storedRequest = (AuthenticationRequest) state.getItem(stateKey,
        MessageType.AUTHORIZATION_REQUEST);
    Assert.assertEquals(scope, storedRequest.getClaims().get("scope"));
    Assert.assertEquals(clientId, storedRequest.getClaims().get("client_id"));
    Assert.assertEquals(responseType, storedRequest.getClaims().get("response_type"));
  }

  @Test
  public void testHttpPostParameters() throws Exception {
    Map<String, Object> requestParameters = new HashMap<String, Object>();
    HttpMethod httpMethod = HttpMethod.POST;
    requestParameters.put("httpMethod", httpMethod);
    HttpArguments httpArguments = service.getRequestParameters(requestParameters);
    Assert.assertEquals(HttpMethod.POST, httpArguments.getHttpMethod());
  }

  @Test
  public void testdoUpdateServiceContextResponseStored()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    AuthenticationResponse response = new AuthenticationResponse();
    response.addClaim("any", "value");
    service.updateServiceContext(response, stateKey);
    Message storedResponse = state.getItem(stateKey, MessageType.AUTHORIZATION_RESPONSE);
    Assert.assertTrue(storedResponse instanceof AuthenticationResponse);
    Assert.assertEquals("value", response.getClaims().get("any"));
  }

  @Test
  public void testdoUpdateServiceContextIdTokenStored() throws MissingRequiredAttributeException,
      ValueException, InvalidClaimException, SerializationException {
    // We have to create a id token that passes the tests
    AuthenticationResponse response = new AuthenticationResponse();
    Date now = new Date();
    response.setSigAlg("none");
    response.setClientId(clientId);
    IDToken idToken = new IDToken();
    idToken.addClaim("iss", issuer);
    idToken.addClaim("sub", "user01");
    idToken.addClaim("aud", clientId);
    idToken.addClaim("exp", new Date(now.getTime() + 1000));
    idToken.addClaim("iat", now);
    idToken.addClaim("nonce", "noncevalue");
    response.addClaim("id_token", idToken.toJwt(null, "none", null, null, null, null, null, null));
    state.storeStateKeyForNonce("noncevalue", stateKey);
    service.updateServiceContext(response, stateKey);
    Message storedIDToken = state.getItem(stateKey, MessageType.VERIFIED_IDTOKEN);
    Message storedResponse = state.getItem(stateKey, MessageType.AUTHORIZATION_RESPONSE);
    Assert.assertNotNull(((AuthenticationResponse) storedResponse).getVerifiedIdToken());
    Assert.assertTrue(storedIDToken instanceof IDToken);
    Assert.assertEquals("noncevalue", storedIDToken.getClaims().get("nonce"));
  }

  @Test
  public void testdoUpdateServiceContextExpiresAt()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    AuthenticationResponse response = new AuthenticationResponse();
    long expires = 3600;
    response.addClaim("expires_in", expires);
    service.updateServiceContext(response, stateKey);
    Message storedResponse = state.getItem(stateKey, MessageType.AUTHORIZATION_RESPONSE);
    Assert.assertTrue(storedResponse instanceof AuthenticationResponse);
    Assert.assertTrue(response.getClaims().containsKey("__expires_at"));
  }

  @Test
  public void testprepareMessageForVerification() {
    AuthenticationResponse response = new AuthenticationResponse();
    service.prepareMessageForVerification(response);
    Assert.assertEquals(serviceContext.getIssuer(), response.getIssuer());
    Assert.assertEquals(serviceContext.getClientId(), response.getClientId());
  }
  
  @Test
  public void testprepareMessageForVerificationNullInput() {
    AuthenticationResponse response = new AuthenticationResponse();
    serviceContext.setBehavior(null);
    serviceContext.getAllow().put("missing_kid", null);
    service.prepareMessageForVerification(response);
    Assert.assertEquals(serviceContext.getIssuer(), response.getIssuer());
    Assert.assertEquals(serviceContext.getClientId(), response.getClientId());
  }

}
