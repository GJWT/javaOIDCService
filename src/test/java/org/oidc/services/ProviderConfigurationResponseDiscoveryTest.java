package org.oidc.services;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.service.base.ServiceContext;

public class ProviderConfigurationResponseDiscoveryTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testGetEndpoint() {
       ServiceContext serviceContext = SERVICE_CONTEXT;
       serviceContext.setIssuer("issuer/");
       ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(serviceContext);
       String endpoint = pcrd.getEndpoint();
       Assert.assertTrue(endpoint.equals());
    }

    @Test
    public void testGetEndpointNullIssuer() {
        ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(SERVICE_CONTEXT);
        String endpoint = pcrd.getEndpoint();
        Assert.assertTrue(endpoint.equals());
    }
}
