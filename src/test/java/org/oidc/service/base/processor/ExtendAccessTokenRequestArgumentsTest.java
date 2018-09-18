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
import org.oidc.msg.oidc.AccessTokenRequest;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link ExtendAccessTokenRequestArguments}.
 */
public class ExtendAccessTokenRequestArgumentsTest
    extends BaseRequestArgumentProcessorTest<ExtendAccessTokenRequestArguments> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    service = new MockService(new AccessTokenRequest());
    requestArguments = new HashMap<String, Object>();
    service.getState().createStateRecord("issuer", "U09NRVJBTkRPTVNUQVRF");
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.addClaim("client_id", "clientIdValue");
    authenticationRequest.addClaim("state", "U09NRVJBTkRPTVNUQVRF");
    authenticationRequest.addClaim("redirect_uri", "http://example.com");
    AuthenticationResponse authenticationResponse = new AuthenticationResponse();
    authenticationResponse.addClaim("client_id", "clientIdValue");
    authenticationResponse.addClaim("state", "U09NRVJBTkRPTVNUQVRF");
    authenticationResponse.addClaim("code", "U09NRUFVVEhPUklaQVRJT05DT0RF");
    service.getState().storeItem(authenticationRequest, "U09NRVJBTkRPTVNUQVRF",
        MessageType.AUTHORIZATION_REQUEST);
    service.getState().storeItem(authenticationResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.AUTHORIZATION_RESPONSE);

  }

  @Override
  protected ExtendAccessTokenRequestArguments constructProcessor() {
    return new ExtendAccessTokenRequestArguments();
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
  }
  
  @Test
  public void testFullMerge() throws RequestArgumentProcessingException {
    service.getPreConstructorArgs().put("state", "U09NRVJBTkRPTVNUQVRF");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("clientIdValue", requestArguments.get("client_id"));
    Assert.assertEquals("U09NRVJBTkRPTVNUQVRF", requestArguments.get("state"));
    Assert.assertEquals("http://example.com", requestArguments.get("redirect_uri"));
    Assert.assertEquals("U09NRUFVVEhPUklaQVRJT05DT0RF", requestArguments.get("code"));
    Assert.assertEquals("authorization_code", requestArguments.get("grant_type"));
    Assert.assertEquals(5, requestArguments.size());
  }

}
