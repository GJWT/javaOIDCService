package org.oidc.services;

import static org.hamcrest.core.StringContains.containsString;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.AddedClaims;
import org.oidc.common.WebFingerException;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.util.Constants;

public class WebfingerTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    @Rule
    ExpectedException thrown = ExpectedException.none();

    @Test
    public void testUpdateServiceContextWrongMethod() throws Exception {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("stateKey is not required to update service context for the WebFinger service");
        AbstractService webfinger = new Webfinger(SERVICE_CONTEXT);
        webfinger.updateServiceContext(null, null);
    }

    @Test
    public void testGetQueryWithDevice() throws Exception{
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("device:p1.example.com", null);
        Assert.assertTrue(query.equals("https://p1.example.com/.well-known/webfinger?resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
    }

    @Test
    public void testGetQueryWithAcct() throws Exception{
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("acct:bob@example.com", null);
        Assert.assertTrue(query.equals("https://example.com/.well-known/webfinger?resource=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard"));
    }

    @Test
    public void testGetQueryWithUnknownSchema() throws Exception{
        thrown.expect(WebFingerException.class);
        thrown.expectMessage(containsString(" has an unknown schema"));
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("www.yahoo.com", null);
    }

    @Test
    public void testGetQueryWithNullResource() throws Exception{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("unknown schema");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery(null, null);
    }

    @Test
    public void testGetQueryWithEmptyResource() throws Exception{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("unknown schema");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("", null);
    }

    @Test
    public void testGetRequestParametersUrl() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String,String> requestArguments = new HashMap<String,String>();
        requestArguments.put("resource", "acct:bob@example.com");

        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder()
                .setOidcIssuers(Arrays.asList("http://webfinger.net/rel/profile-page", "vcard"))
                .buildAddedClaims();
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?resource" +
                "=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard"));
    }

    @Test
    public void testGetRequestParametersAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT, Arrays.asList(Constants.OIDC_ISSUER));
        Map<String,String> requestArguments = new HashMap<String,String>();
        requestArguments.put("resource", "acct:carol@example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?" +
                "resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1" +
                ".0%2Fissuer"));
    }
}
