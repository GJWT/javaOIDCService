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
import org.oidc.msg.oauth2.RefreshAccessTokenRequest;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link ExtendRefreshAccessTokenRequestArguments}.
 */
public class ExtendRefreshAccessTokenRequestArgumentsTest
    extends BaseRequestArgumentProcessorTest<ExtendRefreshAccessTokenRequestArguments> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    service = new MockService(new RefreshAccessTokenRequest());
    requestArguments = new HashMap<String, Object>();
    service.getState().createStateRecord("issuer", "U09NRVJBTkRPTVNUQVRF");
    AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
    accessTokenResponse.addClaim("refresh_token", "U09NRVJFRlJFU0hUT0tFTg==");
    AccessTokenResponse refreshAccessTokenResponse = new AccessTokenResponse();
    refreshAccessTokenResponse.addClaim("refresh_token", "U09NRU5FV1JFRlJFU0hUT0tFTg==");
    service.getState().storeItem(accessTokenResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.TOKEN_RESPONSE);
    service.getState().storeItem(refreshAccessTokenResponse, "U09NRVJBTkRPTVNUQVRF",
        MessageType.REFRESH_TOKEN_RESPONSE);
  }

  @Override
  protected ExtendRefreshAccessTokenRequestArguments constructProcessor() {
    return new ExtendRefreshAccessTokenRequestArguments();
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
  }

  @Test
  public void testFullMerge() throws RequestArgumentProcessingException {
    service.getPreConstructorArgs().put("state", "U09NRVJBTkRPTVNUQVRF");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("U09NRU5FV1JFRlJFU0hUT0tFTg==", requestArguments.get("refresh_token"));
    Assert.assertEquals(2, requestArguments.size());
  }

}
