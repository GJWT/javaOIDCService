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

package org.oidc.service.oauth2;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;

/**
 * Unit tests for {@link ProviderInfoDiscovery}
 */
public class ProviderInfoDiscoveryTest extends BaseServiceTest<ProviderInfoDiscovery> {

  ServiceContext serviceContext;
  String issuer;

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    service = new ProviderInfoDiscovery(serviceContext, null, null);
    issuer = "https://www.example.com";
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testHttpParamsMissingIssuer() throws Exception {
    service.getRequestParameters(new HashMap<String, Object>());
  }

  @Test
  public void testHttpParamsSuccessfulIssuer() throws Exception {
    serviceContext.setIssuer(issuer);
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, Object>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test
  public void testHttpParamsSuccessFulIssuerTrailingSlash() throws Exception {
    serviceContext.setIssuer(issuer + "/");
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, Object>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test(expected = MissingRequiredAttributeException.class)
  public void testUpdateCtxMissingIssuer() throws Exception {
    service.updateServiceContext(buildMinimalResponse(issuer));
  }

  //TODO: Update test. Message is now verified in parse response.
  //@Test(expected = InvalidClaimException.class)
  public void testUpdateCtxInvalidResponseContents() throws Exception {
    ASConfigurationResponse response = buildMinimalResponseWithEndpoints(issuer);
    response.addClaim("revocation_endpoint", Arrays.asList("should", "not", "be", "list"));
    serviceContext.setIssuer(issuer + "/");
    service.updateServiceContext(response);
  }
  
  
  @Test
  public void testUpdateCtxSuccess() throws Exception {
    serviceContext.setIssuer(issuer);
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer));
    ASConfigurationResponse response = service.getServiceContext()
        .getProviderConfigurationResponse();
    Assert.assertNotNull(response);
    Assert.assertTrue(response.verify());
    Assert.assertNotNull(serviceContext.getKeyJar());
    Assert.assertTrue(serviceContext.getEndpoints().isEmpty());
  }

  @Test
  public void testUpdateCtxSuccessMismatchAllowed() throws Exception {
    serviceContext.setIssuer("https://www.example.org");
    Map<String, Boolean> allow = new HashMap<String, Boolean>();
    allow.put(Constants.ALLOW_PARAM_ISSUER_MISMATCH, Boolean.TRUE);
    serviceContext.setAllow(allow);
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer));
    ASConfigurationResponse response = service.getServiceContext()
        .getProviderConfigurationResponse();
    Assert.assertNotNull(response);
    Assert.assertTrue(response.verify());
    Assert.assertNotNull(serviceContext.getKeyJar());
    Assert.assertTrue(serviceContext.getEndpoints().isEmpty());
  }

  @Test(expected = InvalidClaimException.class)
  public void testUpdateCtxFailedMismatch() throws Exception {
    serviceContext.setIssuer("https://www.example.org");
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer + "/"));
  }

  @Test
  public void testUpdateCtxSuccessWithEndpoints() throws Exception {
    serviceContext.setIssuer(issuer);
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponseWithEndpoints(issuer));
    ASConfigurationResponse response = service.getServiceContext()
        .getProviderConfigurationResponse();
    Assert.assertNotNull(response);
    Assert.assertTrue(response.verify());
    Assert.assertNotNull(serviceContext.getKeyJar());
    Assert.assertFalse(serviceContext.getEndpoints().isEmpty());
    Assert.assertTrue(serviceContext.getEndpoints().keySet().size() == 2);
    Assert.assertEquals("https://www.example.org/authorize",
        serviceContext.getEndpoints().get(EndpointName.AUTHORIZATION));
    Assert.assertEquals("https://www.example.org/token",
        serviceContext.getEndpoints().get(EndpointName.TOKEN));
  }

  protected ASConfigurationResponse buildMinimalResponse(String issuer)
      throws InvalidClaimException {
    ASConfigurationResponse response = new ASConfigurationResponse();
    response.addClaim("issuer", issuer);
    response.addClaim("response_types_supported", Arrays.asList("code"));
    response.addClaim("grant_types_supported", Arrays.asList("authorization_code"));
    Assert.assertTrue(response.verify());
    return response;
  }

  protected ASConfigurationResponse buildMinimalResponseWithEndpoints(String issuer)
      throws InvalidClaimException {
    ASConfigurationResponse response = buildMinimalResponse(issuer);
    response.addClaim("authorization_endpoint", "https://www.example.org/authorize");
    response.addClaim("token_endpoint", "https://www.example.org/token");
    return response;
  }
}
