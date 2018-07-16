package org.oidc.services;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.AddedClaims;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.JsonResponseDescriptor;
import org.oidc.msg.Link;
import org.oidc.msg.Message;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;

public class WebfingerTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();
    private static final String OP_BASEURL = "https://example.org/op";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testUpdateServiceContextWrongMethod() throws Exception {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("stateKey is not supported to update service context for the WebFinger service");
        AbstractService webfinger = new Webfinger(SERVICE_CONTEXT);
        webfinger.updateServiceContext(null, null);
    }

    @Test
    public void testGetQueryWithDevice() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("device:p1.example.com");
        Assert.assertTrue(query.equals("https://p1.example.com/.well-known/webfinger?device%3Ap1.example.com"));
    }

    @Test
    public void testGetQueryWithAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("acct:bob@example.com");
        Assert.assertTrue(query.equals("https://example.com/.well-known/webfinger?acct%3Abob%40example.com"));
    }

    @Test
    public void testGetQueryWithWWWSchema() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("www.yahoo.com");
        Assert.assertTrue(query.equals("https://www.yahoo.com/.well-known/webfinger?https%3A%2F%2Fwww.yahoo.com"));
    }

    @Test
    public void testGetQueryWithNullResource() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty url");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery(null);
    }

    @Test
    public void testGetQueryWithEmptyResource() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty url");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("");
    }

    @Test
    public void testGetRequestParametersNullRequestArguments() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null requestArguments");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        webfinger.getRequestParameters(null);
    }

    @Test
    public void testGetRequestParametersNullResource() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder().setResource("resource").buildAddedClaims();
        webfinger.setAddedClaims(addedClaims);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", null);
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getHttpMethod().equals(HttpMethod.GET));
        Assert.assertTrue(httpArguments.getUrl().equals("https://resource/.well-known/webfinger?https%3A%2F%2Fresource"));
    }

    @Test
    public void testGetRequestParametersNullResourceAndNullAddedClaimsResource() throws Exception {
        ServiceContext serviceContext = SERVICE_CONTEXT;
        serviceContext.setBaseUrl("baseUrl");
        Webfinger webfinger = new Webfinger(serviceContext);
        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder().setResource(null).buildAddedClaims();
        webfinger.setAddedClaims(addedClaims);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", null);
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getHttpMethod().equals(HttpMethod.GET));
        Assert.assertTrue(httpArguments.getUrl().equals("https://baseUrl/.well-known/webfinger?https%3A%2F%2FbaseUrl"));
    }

    @Test
    public void testGetRequestParametersNullResourceAndNullAddedClaimsResourceAndNullBaseUrl() throws Exception {
        thrown.expect(MissingRequiredAttributeException.class);
        thrown.expectMessage("resource attribute is missing");
        ServiceContext serviceContext = SERVICE_CONTEXT;
        serviceContext.setBaseUrl(null);
        Webfinger webfinger = new Webfinger(serviceContext);
        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder().setResource(null).buildAddedClaims();
        webfinger.setAddedClaims(addedClaims);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", null);
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
    }

    @Test
    public void testGetRequestParametersUrl() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", "acct:bob@example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?acct%3Abob%40example.com"));
    }

    @Test
    public void testGetRequestParametersAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", "acct:carol@example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?acct%3Acarol%40example.com"));
    }

    @Test
    public void testGetRequestParameters() throws MalformedURLException, WebFingerException, MissingRequiredAttributeException, ValueException, UnsupportedEncodingException {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String, String> requestParametersMap = new HashMap<String, String>() {{
            put("example.com", "example.com");
            put("example.com:8080", "example.com:8080");
            put("example.com/path", "example.com");
            put("example.com?query", "example.com");
            put("example.com#fragment", "example.com");
            put("example.com:8080/path?query#fragment", "example.com:8080");
            put("http://example.com", "example.com");
            put("http://example.com:8080", "example.com:8080");
            put("http://example.com/path", "example.com");
            put("http://example.com?query", "example.com");
            put("http://example.com#fragment", "example.com");
            put("http://example.com:8080/path?query#fragment", "example.com:8080");
            put("nov@example.com", "example.com");
            put("nov@example.com:8080", "example.com:8080");
            put("nov@example.com/path", "example.com");
            put("nov@example.com?query", "example.com");
            put("nov@example.com#fragment", "example.com");
            put("nov@example.com:8080/path?query#fragment", "example.com:8080");
            put("acct:nov@matake.jp", "matake.jp");
            put("acct:nov@example.com:8080", "example.com:8080");
            put("acct:nov@example.com/path", "example.com");
            put("acct:nov@example.com?query", "example.com");
            put("acct:nov@example.com#fragment", "example.com");
            put("acct:nov@example.com:8080/path?query#fragment", "example.com:8080");
            put("device:192.168.2.1", "192.168.2.1");
            put("device:192.168.2.1:8080", "192.168.2.1");
            put("device:192.168.2.1/path", "192.168.2.1");
            put("device:192.168.2.1?query", "192.168.2.1");
            put("device:192.168.2.1#fragment", "192.168.2.1");
            put("device:192.168.2.1/path?query#fragment", "192.168.2.1");
        }};

        HttpArguments requestParams;
        Map<String,String> input = new HashMap<>();
        String[] requestParamsSplit;
        for(String key : requestParametersMap.keySet()) {
            input.put("resource", key);
            requestParams = webfinger.getRequestParameters(input);
            requestParamsSplit = requestParams.getUrl().split("\\?");
            if(!requestParamsSplit[0].equals(String.format(Constants.WEB_FINGER_URL, requestParametersMap.get(key)))) {
                throw new AssertionError("result does not match expected webFinger url");
            }
        }
    }

    @Test
    public void testWebfingerEndToEnd() throws Exception {
        ServiceConfig serviceConfig = new ServiceConfig(true, true);
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT, serviceConfig);
        Map<String,String> requestArguments = new HashMap<>();
        requestArguments.put("resource", "foobar@example.org");
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.org/.well-known/webfinger?acct%3Afoobar%40example.org"));
        HashMap<String, Object> claims = new HashMap<>();
        Link linkInfo = new Link();
        linkInfo.addClaim("rel", "rel");
        linkInfo.addClaim("href", "href");
        linkInfo.addClaim("type", "type");
        Link secondLinkInfo = new Link();
        secondLinkInfo.addClaim("rel", "http://openid.net/specs/connect/1.0/issuer");
        secondLinkInfo.addClaim("href", OP_BASEURL);
        secondLinkInfo.addClaim("type", "type2");
        claims.put("links", Arrays.asList(linkInfo, secondLinkInfo));
        JsonResponseDescriptor jrd = new JsonResponseDescriptor(claims);
        Message parsedResponse = webfinger.parseResponse(jrd.toJson());
        Assert.assertTrue(parsedResponse instanceof JsonResponseDescriptor);
        Map<String,Object> expectedClaims = new HashMap<>();
        expectedClaims.put("rel", "rel");
        expectedClaims.put("href", "href");
        expectedClaims.put("type", "type");
        Map<String,Object> secondExpectedClaims = new HashMap<>();
        secondExpectedClaims.put("rel", "http://openid.net/specs/connect/1.0/issuer");
        secondExpectedClaims.put("href", OP_BASEURL);
        secondExpectedClaims.put("type", "type2");
        List<Link> links = (List<Link>) parsedResponse.getClaims().get("links");
        Assert.assertTrue(expectedClaims.values().containsAll(links.get(0).getClaims().values()));
        Assert.assertTrue(secondExpectedClaims.values().containsAll(links.get(1).getClaims().values()));
        
        webfinger.updateServiceContext(parsedResponse);
        Assert.assertTrue(webfinger.getServiceContext().getIssuer().equals(OP_BASEURL));
    }
}
