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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;

/**
 * Unit tests for {@link Authentication}.
 */
public class AuthenticationTest extends BaseServiceTest<Authentication> {

  ServiceContext serviceContext;
  String issuer;
  Map<String, Object> map = new HashMap<String, Object>();

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    service = new Authentication(serviceContext, new InMemoryStateImpl(), null);
    service.setEndpoint("https://www.example.com/authorize");
    List<String> redirectUris = new ArrayList<String>();
    redirectUris.add("https://example.com/cb");
    serviceContext.setRedirectUris(redirectUris);
    issuer = "https://www.example.com";
    serviceContext.setIssuer(issuer);
    map.clear();
    map.put("response_type", "code");
    map.put("scope", "openid");
    map.put("client_id", "clientid_x");
  }

  @Test
  public void testHttpGetParametersMinimal() throws Exception {
    HttpArguments httpArguments = service.getRequestParameters(map);
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
    Assert.assertTrue(httpArguments.getUrl().startsWith("https://www.example.com/authorize"));
    Assert.assertTrue(httpArguments.getUrl().contains("client_id=clientid_x"));
    Assert.assertTrue(httpArguments.getUrl().contains("scope=openid"));
    Assert.assertTrue(httpArguments.getUrl().contains("response_type=code"));
    Assert
        .assertTrue(httpArguments.getUrl().contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcb"));
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
