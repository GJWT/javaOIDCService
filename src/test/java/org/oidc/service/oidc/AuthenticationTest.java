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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;

/**
 * Unit tests for {@link Authentication}.
 */
public class AuthenticationTest extends BaseServiceTest<Authentication> {

  ServiceContext serviceContext;
  String issuer;
  Map<String, Object> map = new HashMap<String, Object>();
  State state;

  String endpoint = "https://www.example.com/authorize";
  String callback = "https://example.com/cb";
  String responseType = "code";
  String scope = "openid";
  String clientId = "clientid_x";

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    state = new InMemoryStateImpl();
    service = new Authentication(serviceContext, state, null);
    service.setEndpoint(endpoint);
    List<String> redirectUris = new ArrayList<String>();
    redirectUris.add(callback);
    serviceContext.setRedirectUris(redirectUris);
    issuer = "https://www.example.com";
    serviceContext.setIssuer(issuer);
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
    AuthenticationRequest storedRequest =
        (AuthenticationRequest) state.getItem(stateKey, MessageType.AUTHORIZATION_REQUEST);
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

}
