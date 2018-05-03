package org.oidc.services;

import static org.hamcrest.core.StringContains.containsString;

import com.auth0.msg.Claim;
import com.auth0.msg.ClaimType;
import com.auth0.msg.JsonResponseDescriptor;
import com.auth0.msg.Message;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.AddedClaims;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.service.AbstractService;
import org.oidc.service.LinkInfo;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;

public class WebfingerTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();
    private static final String OP_BASEURL = "https://example.org/op";

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
    public void testGetQueryWithDevice() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("device:p1.example.com");
        Assert.assertTrue(query.equals("https://p1.example.com/.well-known/webfinger?resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
    }

    @Test
    public void testGetQueryWithAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("acct:bob@example.com");
        Assert.assertTrue(query.equals("https://example.com/.well-known/webfinger?resource=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard"));
    }

    @Test
    public void testGetQueryWithUnknownSchema() throws Exception {
        thrown.expect(WebFingerException.class);
        thrown.expectMessage(containsString(" has an unknown schema"));
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery("www.yahoo.com");
    }

    @Test
    public void testGetQueryWithNullResource() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("unknown schema");
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        String query = webfinger.getQuery(null);
    }

    @Test
    public void testGetQueryWithEmptyResource() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("unknown schema");
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
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?resource" +
                "=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard"));
    }

    @Test
    public void testGetRequestParametersAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String, String> requestArguments = new HashMap<String, String>();
        requestArguments.put("resource", "acct:carol@example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?" +
                "resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1" +
                ".0%2Fissuer"));
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
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String,String> requestArguments = new HashMap<>();
        requestArguments.put("resource", "foobar@example.org");
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.org/.well-known/webfinger?resource=acct%3Afoobar%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));

        Message parsedResponse = webfinger.parseResponse("{\"subject\": \"acct:foobar@example.org\",\"links\": [{\"rel\": \"http://openid.net/specs/connect/1.0/issuer\",\"href\": \"https://example.org/op\"}],\"expires\": \"2018-02-04T11:08:41Z\"}");
        Assert.assertTrue(parsedResponse instanceof JsonResponseDescriptor);
        Claim subject = new Claim(Constants.SUBJECT);
        Claim links = new Claim(Constants.LINKS);
        Claim expires = new Claim(Constants.EXPIRES);
        Set<Claim> setOfClaims = new HashSet<>();
        setOfClaims.add(subject);
        setOfClaims.add(links);
        setOfClaims.add(expires);
        Assert.assertTrue(parsedResponse.getClaims().keySet().equals(setOfClaims));
        LinkInfo linkInfo = (LinkInfo) parsedResponse.getClaims().get(links);
        Assert.assertTrue(linkInfo.getRel().equals("http://openid.net/specs/connect/1.0/issuer"));
        Assert.assertTrue(linkInfo.gethRef().equals("https://example.org/op"));
        webfinger.updateServiceContext(parsedResponse);
        Assert.assertTrue(SERVICE_CONTEXT.getIssuer().equals(OP_BASEURL));
    }
}
