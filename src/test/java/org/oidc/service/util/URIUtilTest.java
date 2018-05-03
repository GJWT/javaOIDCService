package org.oidc.service.util;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.ValueException;

public class URIUtilTest {

    @Rule
    ExpectedException thrown = ExpectedException.none();

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
