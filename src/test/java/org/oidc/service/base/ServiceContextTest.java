package org.oidc.service.base;

import com.auth0.msg.KeyJar;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.ValueException;

public class ServiceContextTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testFileNameFromWebnameNullUrl() throws Exception{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty webName");
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.fileNameFromWebname(null);
    }

    @Test
    public void testFileNameFromWebnameEmptyUrl() throws Exception{
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null or empty webName");
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.fileNameFromWebname("");
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameDoesntStartWithBaseUrl() throws Exception {
        thrown.expect(ValueException.class);
        thrown.expectMessage("Webname does not match baseUrl");
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("baseUrl")
                .buildServiceContext();
        KeyJar keyJar = new KeyJar();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        serviceContext.fileNameFromWebname("webName");
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        KeyJar keyJar = new KeyJar();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com/1234");
        Assert.assertTrue(fileName.equals("1234"));
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameDoesntStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        KeyJar keyJar = new KeyJar();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com:1234");
        Assert.assertTrue(fileName.equals(":1234"));
    }
}
