package org.oauth2.services;


import static org.hamcrest.core.StringContains.containsString;

import com.auth0.msg.KeyJar;
import com.auth0.msg.ProviderConfigurationResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oauth2.ProviderConfigurationResponseDiscovery;
import org.oidc.common.HttpMethod;
import org.oidc.common.OidcServiceException;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;

public class ProviderConfigurationResponseDiscoveryTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testGetRequestParametersWithEmptyServiceContextIssuer() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty issuer");
        ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(SERVICE_CONTEXT);
        pcrd.getRequestParameters();
    }

    @Test
    public void testGetRequestParametersWithIssuerEndingInForwardSlash() {
        ServiceContext serviceContext = SERVICE_CONTEXT;
        serviceContext.setIssuer("issuer/");
        ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(serviceContext);
        HttpArguments httpArguments = pcrd.getRequestParameters();
        //Assert.assertTrue(httpArguments.getUrl().equals());
        Assert.assertTrue(httpArguments.getHttpMethod().equals(HttpMethod.GET));
    }

    @Test
    public void testUpdateServiceContext() throws Exception{
        ServiceContext serviceContext = SERVICE_CONTEXT;
        KeyJar keyJar = new KeyJar();
        serviceContext.setIssuer("issuer");
        serviceContext.setKeyJar(keyJar);
        HashMap<String, Object> pcrClaims = new HashMap<>();
        pcrClaims.put("issuer", "issuerValue/");
        pcrClaims.put("authorizationEndpoint", "authorizationEndpoint");
        ProviderConfigurationResponse pcrForServiceContext = new ProviderConfigurationResponse(pcrClaims);
        serviceContext.setProviderConfigurationResponse(pcrForServiceContext);
        ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(serviceContext);
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("issuer", "issuerValue/");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        pcrd.updateServiceContext(pcr);
    }

    @Test
    public void testUpdateServiceContextWithIssuerMismatch() throws Exception{
        thrown.expect(OidcServiceException.class);
        thrown.expectMessage(containsString("Provider config issuer mismatch "));

        ServiceContext serviceContext = SERVICE_CONTEXT;
        serviceContext.setIssuer("issuer/");
        Map<String,Boolean> allow = new HashMap<>();
        allow.put("notIssuerMismatch", true);
        serviceContext.setAllow(allow);
        HashMap<String, Object> pcrClaims = new HashMap<>();
        pcrClaims.put("issuer", "issuerValue/");
        ProviderConfigurationResponse pcrForServiceContext = new ProviderConfigurationResponse(pcrClaims);
        serviceContext.setProviderConfigurationResponse(pcrForServiceContext);
        ProviderConfigurationResponseDiscovery pcrd = new ProviderConfigurationResponseDiscovery(serviceContext);
        pcrd.updateServiceContext(pcrForServiceContext);
    }
}
