package org.oidc.service.util;

import static org.hamcrest.core.StringContains.containsString;

import com.auth0.msg.ClaimType;
import com.auth0.msg.Message;
import com.auth0.msg.ProviderConfigurationResponse;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;

public class ServiceUtilTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testGetQueryReferenceNullUrl() throws Exception{
        thrown.expect(MalformedURLException.class);
        thrown.expectMessage("null or empty url");
        ServiceUtil.getUrlInfo(null);
    }

    @Test
    public void testGetQueryReferenceEmptyUrl() throws Exception{
        thrown.expect(MalformedURLException.class);
        thrown.expectMessage("null or empty url");
        ServiceUtil.getUrlInfo("");
    }

    @Test
    public void testGetUrlQueryReferenceWithQueryIncluded() throws Exception{
        String url = ServiceUtil.getUrlInfo("https://www.google.co.in/search?q=gnu&rlz=1C1CHZL_enIN71" +
                "4IN715&oq=gnu&aqs=chrome..69i57j69i60l5.653j0j7&sourceid=chrome&ie=UTF" +
                "-8#q=geeks+for+geeks+java");
        Assert.assertTrue(url.equals("q=gnu&rlz=1C1CHZL_enIN714IN715&oq=gnu&aqs=chrome..69i5" +
                "7j69i60l5.653j0j7&sourceid=chrome&ie=UTF-8"));
    }

    @Test
    public void testGetUrlQueryReferenceWithQueryExcluded() throws Exception{
        String url = ServiceUtil.getUrlInfo("https://www.google.co.in/#q=geeks+for+geeks+java");
        Assert.assertTrue(url.equals("q=geeks+for+geeks+java"));
    }

    @Test
    public void testGetHttpBodyWithSerializationTypeUrlEncoded() throws UnsupportedSerializationTypeException {
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, "issuer");
        Message request = new ProviderConfigurationResponse(claims);
        String httpBody = ServiceUtil.getHttpBody(request, SerializationType.URL_ENCODED);
        Assert.assertTrue(httpBody.equals());
    }

    @Test
    public void testGetHttpBodyWithSerializationTypeJson() throws UnsupportedSerializationTypeException {
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, "issuer");
        Message request = new ProviderConfigurationResponse(claims);
        String httpBody = ServiceUtil.getHttpBody(request, SerializationType.JSON);
        Assert.assertTrue(httpBody.equals());
    }

    @Test
    public void testGetHttpBodyWithIncorrectSerializationType() throws UnsupportedSerializationTypeException {
        thrown.expect(UnsupportedSerializationTypeException.class);
        thrown.expectMessage(containsString("Unsupported content type: "));
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, "issuer");
        Message request = new ProviderConfigurationResponse(claims);
        ServiceUtil.getHttpBody(request, SerializationType.JWT);
    }
}
