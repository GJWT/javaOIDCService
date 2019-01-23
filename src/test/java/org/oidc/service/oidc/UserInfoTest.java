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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.OpenIDSchema;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;

/**
 * Unit tests for {@link UserInfo}.
 */
public class UserInfoTest extends BaseServiceTest<UserInfo> {

  ServiceContext serviceContext;
  String issuer = "https://www.example.com";
  State state;
  String stateKey;

  String endpoint = "https://www.example.com/token";
  String clientId = "clientid_x";

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    state = new InMemoryStateImpl();
    stateKey = state.createStateRecord(issuer, null);
    service = new UserInfo(serviceContext, state, null);
    service.setEndpoint(endpoint);
    serviceContext.setIssuer(issuer);
    serviceContext.setKeyJar(new KeyJar());
    serviceContext.setBehavior(new RegistrationResponse());
    serviceContext.getBehavior().getClaims().put("userinfo_signed_response_alg", "RS256");
    serviceContext.getBehavior().getClaims().put("userinfo_encrypted_response_alg", "RSA1_5");
    serviceContext.getBehavior().getClaims().put("userinfo_encrypted_response_enc", "A128GCM");
    serviceContext.getAllow().put("missing_kid", true);
    AuthenticationResponse resp = new AuthenticationResponse();
    resp.addClaim("access_token", "accesstoken");
    state.storeItem(resp, stateKey, MessageType.AUTHORIZATION_RESPONSE);
    Map<String, Object> preConstructorArgs = new HashMap<String, Object>();
    preConstructorArgs.put("state", stateKey);
    service.setPreConstructorArgs(preConstructorArgs);
  }

  @Test
  public void testHttpGetParametersMinimal() throws Exception {
    HttpArguments httpArguments = service.getRequestParameters(null);
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
    Assert.assertTrue(httpArguments.getUrl().startsWith(endpoint));
    // TODO: Should we not use header to place the bearer token?
    Assert.assertTrue(httpArguments.getUrl().contains("access_token=accesstoken"));
  }

  // @Test
  public void testdoUpdateServiceContextResponseStored()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    OpenIDSchema response = new OpenIDSchema();
    response.addClaim("sub", "joe");
    service.updateServiceContext(response, stateKey);
    Message storedResponse = state.getItem(stateKey, MessageType.USER_INFO);
    Assert.assertTrue(storedResponse instanceof OpenIDSchema);
    Assert.assertEquals("joe", response.getClaims().get("sub"));
  }

  private void storeIdToken(String sub) throws SerializationException {
    AccessTokenResponse tokenResponse = new AccessTokenResponse();
    tokenResponse.addClaim("token_type", "bearer");
    tokenResponse.addClaim("access_token", "value");
    Date now = new Date();
    tokenResponse.setSigAlg("none");
    tokenResponse.setClientId(clientId);
    IDToken idToken = new IDToken();
    idToken.addClaim("iss", issuer);
    idToken.addClaim("sub", sub);
    idToken.addClaim("aud", clientId);
    idToken.addClaim("exp", new Date(now.getTime() + 1000));
    idToken.addClaim("iat", now);
    idToken.addClaim("nonce", "noncevalue");
    tokenResponse.addClaim("id_token",
        idToken.toJwt(null, "none", null, null, null, null, null, null));
    state.storeItem(tokenResponse, stateKey, MessageType.TOKEN_RESPONSE);
  }

  @Test(expected = InvalidClaimException.class)
  public void testpostParseResponseSubNotMatch() throws MissingRequiredAttributeException,
      ValueException, InvalidClaimException, SerializationException, DeserializationException {
    // We store accestoken response containing id token to state db
    // The response sub should be the same
    storeIdToken("sam");
    OpenIDSchema response = new OpenIDSchema();
    response.addClaim("sub", "joe");
    Message resp = service.postParseResponse(response, stateKey);
  }

  @Test
  public void testpostParseResponseSubMatch() throws MissingRequiredAttributeException,
      ValueException, InvalidClaimException, SerializationException, DeserializationException {
    // We store accestoken response containing id token to state db
    // The response sub should be the same
    storeIdToken("joe");
    OpenIDSchema response = new OpenIDSchema();
    response.addClaim("sub", "joe");
    Message resp = service.postParseResponse(response, stateKey);
    Assert.assertTrue(resp instanceof OpenIDSchema);
    Assert.assertEquals("joe", response.getClaims().get("sub"));
  }

  // TODO : test aggregated claims

  @Test
  public void testprepareMessageForVerification() {
    OpenIDSchema response = new OpenIDSchema();
    service.prepareMessageForVerification(response);
    // There is no simple way to test parameters are set except cobertura report
  }

  @Test
  public void testprepareMessageForVerificationNullInput() {
    OpenIDSchema response = new OpenIDSchema();
    serviceContext.setBehavior(null);
    serviceContext.getAllow().put("missing_kid", null);
    service.prepareMessageForVerification(response);
    // There is no simple way to test parameters are set except cobertura report
  }

}
