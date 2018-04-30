package org.oidc.service.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.ValueException;

public class URIUtilTest {

    @Rule
    ExpectedException thrown = ExpectedException.none();

    @Test
    public void testUrlEncodeUTF8NullMap() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null map");
        URIUtil.urlEncodeUTF8(null);
    }

    @Test
    public void testUrlEncodeUTF8() {
        Map<String,List<String>> parameters = new HashMap<>();
        parameters.put("resource", Arrays.asList("device:p1.example.com"));
        parameters.put("rel", Arrays.asList("http://openid.net/specs/connect/1.0/issuer"));
        String encodedUrl = URIUtil.urlEncodeUTF8(parameters);
        Assert.assertTrue(encodedUrl.equals("resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
    }

    @Test
    public void testNormalizeUrlNullUrl() throws ValueException{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty url");
        URIUtil.normalizeUrl(null);
    }

    @Test
    public void testNormalizeUrlEmptyUrl() throws ValueException{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty url");
        URIUtil.normalizeUrl("");
    }

    @Test
    public void testNormalizeUrl() throws ValueException{
        String normalizedUrl = URIUtil.normalizeUrl("foobar@example.org");
        Assert.assertTrue(normalizedUrl.equals("acct:foobar@example.org"));
    }

    @Test
    public void testNormalizeUrlThatsAlreadyBeenNormalizedForDevice() throws ValueException{
        String normalizedUrl = URIUtil.normalizeUrl("device:p1.example.com");
        Assert.assertTrue(normalizedUrl.equals("device:p1.example.com"));
    }

    @Test
    public void testNormalizeUrlThatsAlreadyBeenNormalizedForAcct() throws ValueException{
        String normalizedUrl = URIUtil.normalizeUrl("acct:bob@example.com");
        Assert.assertTrue(normalizedUrl.equals("acct:bob@example.com"));
    }
}
