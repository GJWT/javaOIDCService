package org.oidc.service.util;

import java.net.MalformedURLException;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

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
    public void testGetUrlQueryReferenceWithQueryExcluded() throws Exception{
        String url = ServiceUtil.getUrlInfo("https://www.google.co.in/?gfe_rd=cr&ei=ptYq" +
                "WK26I4fT8gfth6CACg#q=geeks+for+geeks+java");
        Assert.assertTrue(url.equals("q=gnu&rlz=1C1CHZL_enIN714IN715&oq=gnu&aqs=chrome..69i57j69i60l5.653j0j7&" +
                "sourceid=chrome&ie=UTF-8"));
    }

    @Test
    public void testGetUrlQueryReferenceWithQueryIncluded() throws Exception{
        String url = ServiceUtil.getUrlInfo("https://www.google.co.in/#q=geeks+for+geeks+java");
        Assert.assertTrue(url.equals("q=geeks+for+geeks+java"));
    }

    /*@Test
    public void testGetHttpBodyWithSerializationTypeUrlEncoded() {
        ServiceUtil.getHttpBody(new AuthorizationResponse(), SerializationType.URL_ENCODED);
    }

    @Test
    public void testGetHttpBodyWithSerializationTypeJson() {
        ServiceUtil.getHttpBody(new AuthorizationResponse(), SerializationType.JSON);
    }

    @Test
    public void testGetHttpBodyWithIncorrectSerializationType() {
        thrown.expect(UnsupportedContentTypeException.class);
        thrown.expectMessage(containsString("Unsupported content type: "));
        ServiceUtil.getHttpBody(new AuthorizationResponse(), SerializationType.JWT);
    }*/
}
