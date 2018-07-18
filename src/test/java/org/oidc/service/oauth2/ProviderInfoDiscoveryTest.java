package org.oidc.service.oauth2;

import java.util.HashMap;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;

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
  public void testMissingIssuer() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    service.getRequestParameters(new HashMap<String, String>());
  }

  @Test
  public void testSuccessfulIssuer() throws Exception {
    serviceContext.setIssuer(issuer);
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    System.out.println(service.getServiceContext().getIssuer());
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test
  public void testSuccessFulIssuerTrailingSlash() throws Exception {
    serviceContext.setIssuer(issuer + "/");
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    System.out.println(service.getServiceContext().getIssuer());
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals("https://www.example.com/.well-known/openid-configuration",
        httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }
}
