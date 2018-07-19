package org.oidc.service.oauth2;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;

/**
 * Unit tests for {@link ProviderInfoDiscovery}
 */
public class ProviderInfoDiscoveryTest {

  ServiceContext serviceContext;
  String issuer;

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    issuer = "https://www.example.com";
  }

  @Test(expected = MissingRequiredAttributeException.class)
  public void testHttpParamsMissingIssuer() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    service.getRequestParameters(new HashMap<String, String>());
  }

  @Test
  public void testHttpParamsSuccessfulIssuer() throws Exception {
    serviceContext.setIssuer(issuer);
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test
  public void testHttpParamsSuccessFulIssuerTrailingSlash() throws Exception {
    serviceContext.setIssuer(issuer + "/");
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }
  
  @Test(expected = MissingRequiredAttributeException.class)
  public void testUpdateCtxMissingIssuer() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    service.updateServiceContext(buildMinimalResponse(issuer));
  }
  
  @Test
  public void testUpdateCtxSuccess() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    serviceContext.setIssuer(issuer);
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer));
    ASConfigurationResponse response = service.getServiceContext().getProviderConfigurationResponse();
    Assert.assertNotNull(response);
    Assert.assertTrue(response.verify());
  }

  @Test
  public void testUpdateCtxSuccessMismatchAllowed() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    serviceContext.setIssuer("https://www.example.org");
    Map<String, Boolean> allow = new HashMap<String, Boolean>();
    allow.put(Constants.ALLOW_PARAM_ISSUER_MISMATCH, Boolean.TRUE);
    serviceContext.setAllow(allow);
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer));
    ASConfigurationResponse response = service.getServiceContext().getProviderConfigurationResponse();
    Assert.assertNotNull(response);
    Assert.assertTrue(response.verify());
  }

  @Test(expected = InvalidClaimException.class)
  public void testUpdateCtxFailedMismatch() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    serviceContext.setIssuer("https://www.example.org");
    Assert.assertNull(service.getServiceContext().getProviderConfigurationResponse());
    service.updateServiceContext(buildMinimalResponse(issuer + "/"));
  }
  
  protected ASConfigurationResponse buildMinimalResponse(String issuer) {
    ASConfigurationResponse response = new ASConfigurationResponse();
    response.addClaim("issuer", issuer);
    response.addClaim("response_types_supported", Arrays.asList("code"));
    response.addClaim("grant_types_supported", Arrays.asList("authorization_code"));
    return response;
  }
}
