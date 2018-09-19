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

package org.oidc.service.base.processor;

import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.MessageType;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link ExtendUserInfoRequestArgumentsTest}.
 */
public class ExtendUserInfoRequestArgumentsTest
    extends BaseRequestArgumentProcessorTest<ExtendUserInfoRequestArguments> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
    service.getPreConstructorArgs().put("state", "U09NRVJBTkRPTVNUQVRF");
    service.getState().createStateRecord("issuer", "U09NRVJBTkRPTVNUQVRF");
    AuthenticationResponse authenticationResponse = new AuthenticationResponse();
    authenticationResponse.addClaim("access_token", "U09NRUFDQ0VTU1RPS0VO");
    AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
    accessTokenResponse.addClaim("access_token", "U09NRU9USEVSQUNDRVNTVE9LRU4=");
    AccessTokenResponse refreshAccessTokenResponse = new AccessTokenResponse();
    refreshAccessTokenResponse.addClaim("access_token", "U09NRVJFRlJFU0hFRENDRVNTVE9LRU4=");
    service.getState().storeItem(authenticationResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.AUTHORIZATION_RESPONSE);
    service.getState().storeItem(accessTokenResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.TOKEN_RESPONSE);
    service.getState().storeItem(refreshAccessTokenResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.REFRESH_TOKEN_RESPONSE);
  }

  @Override
  protected ExtendUserInfoRequestArguments constructProcessor() {
    return new ExtendUserInfoRequestArguments();
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testNoArguments() throws RequestArgumentProcessingException {
    service.getPreConstructorArgs().remove("state");
    processor.processRequestArguments(requestArguments, service);
  }

  @Test
  public void testPreserveAccessToken() throws RequestArgumentProcessingException {
    requestArguments.put("access_token", "U09NRVBSRVNFUlZFRENDRVNTVE9LRU4=");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("U09NRVBSRVNFUlZFRENDRVNTVE9LRU4=", requestArguments.get("access_token"));
  }

  @Test
  public void testFullMerge() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("U09NRVJFRlJFU0hFRENDRVNTVE9LRU4=", requestArguments.get("access_token"));
  }

  @Test
  public void testNoAccessTokenInRefreshTokenResponse() throws RequestArgumentProcessingException {
    service.getState().storeItem(new AccessTokenResponse(), "U09NRVJBTkRPTVNUQVRF",
        MessageType.REFRESH_TOKEN_RESPONSE);
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("U09NRU9USEVSQUNDRVNTVE9LRU4=", requestArguments.get("access_token"));
  }

  @Test
  public void testNoAccessTokenInAnyTokenResponse() throws RequestArgumentProcessingException {
    service.getState().storeItem(new AccessTokenResponse(), "U09NRVJBTkRPTVNUQVRF",
        MessageType.REFRESH_TOKEN_RESPONSE);
    service.getState().storeItem(new AccessTokenResponse(), "U09NRVJBTkRPTVNUQVRF",
        MessageType.TOKEN_RESPONSE);
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("U09NRUFDQ0VTU1RPS0VO", requestArguments.get("access_token"));
  }

}
