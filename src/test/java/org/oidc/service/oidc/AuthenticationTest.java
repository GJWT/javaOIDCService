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

import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;

import org.oidc.service.base.ServiceContext;

/**
 * Unit tests for {@link Authentication}.
 */
public class AuthenticationTest extends BaseServiceTest<Authentication> {

  ServiceContext serviceContext;
  String issuer;

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    service = new Authentication(serviceContext, null, null);
    issuer = "https://www.example.com";
    serviceContext.setIssuer(issuer);
  }

  @Test(expected = MissingRequiredAttributeException.class)
  public void testHttpGetParametersMissingUrl() throws Exception {
    service.getRequestParameters(new HashMap<String, Object>());
  }

  @Test
  public void testHttpGetParameters() throws Exception {
    ((Authentication)service).setEndpoint("https://www.example.com/authorize");
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, Object>());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test
  public void testHttpPostParameters() throws Exception {
    ((Authentication)service).setEndpoint("https://www.example.com/authorize");
    Map<String, Object> requestParameters = new HashMap<String, Object>();
    HttpMethod httpMethod = HttpMethod.POST;
    requestParameters.put("httpMethod", httpMethod);
    HttpArguments httpArguments = service.getRequestParameters(requestParameters);
    Assert.assertEquals(HttpMethod.POST, httpArguments.getHttpMethod());
  }

}
