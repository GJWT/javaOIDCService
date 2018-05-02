package org.oidc.service.base;

import com.auth0.msg.ClaimType;
import com.auth0.msg.KeyJar;
import com.auth0.msg.ProviderConfigurationResponse;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.FileOrUrl;
import org.oidc.common.KeySpecifications;
import org.oidc.common.ValueException;

public class ServiceContextTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final KeyJar keyJar = new KeyJar();

    @Test
    public void testImportKeysNullKeySpecifications() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("null keySpecifications");
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.importKeys(null);
    }

    @Test
    public void testImportKeysWithFile() {
        ServiceContext serviceContext = new ServiceContext();
        Assert.assertTrue(serviceContext.getKeyJar().getKeyBundle().getKeys().size() == 0);
        Map<FileOrUrl,KeySpecifications> keySpecificationsMap = new HashMap<>();
        KeySpecifications keySpecifications = new KeySpecifications("fileName.txt", "rsa");
        keySpecificationsMap.put(FileOrUrl.FILE, keySpecifications);
        serviceContext.importKeys(keySpecificationsMap);
        Assert.assertTrue(serviceContext.getKeyJar().getKeyBundle().getKeys().size() == 1);
    }

    @Test
    public void testImportKeysWithUrl() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("baseUrl")
                .buildServiceContext();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        Assert.assertTrue(serviceContext.getKeyJar().getKeyBundle().getKeys().size() == 0);
        Map<FileOrUrl,KeySpecifications> keySpecificationsMap = new HashMap<>();
        KeySpecifications keySpecifications = new KeySpecifications("www.yahoo.com", "rsa");
        keySpecificationsMap.put(FileOrUrl.URL, keySpecifications);
        serviceContext.importKeys(keySpecificationsMap);
        Assert.assertTrue(serviceContext.getKeyJar().getKeyBundle().getKeys().size() == 1);
    }

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
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        serviceContext.fileNameFromWebname("webName");
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com/1234");
        Assert.assertTrue(fileName.equals("1234"));
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameDoesntStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com:1234");
        Assert.assertTrue(fileName.equals(":1234"));
    }

    @Test
    public void testGenerateRequestUrisWithNullIssuer() throws NoSuchAlgorithmException {
        ServiceContext serviceContext = new ServiceContext();
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, null);
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        serviceContext.generateRequestUris("/url");
    }

    @Test
    public void testGenerateRequestUrisWithForwardSlash() throws NoSuchAlgorithmException {
        ServiceContext serviceContext = new ServiceContext();
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, "issuerValue");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("/url");
        //Assert.assertTrue(requestUris.equals());
    }

    /**
     * PCR = ProviderConfigurationResponse
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testGenerateRequestUrisWithMultipleClaimsForPCR() throws NoSuchAlgorithmException {
        ServiceContext serviceContext = new ServiceContext();
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, Arrays.asList("issuerValue", "issuerValue2"));
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("/url");
        //Assert.assertTrue(requestUris.equals());
    }

    @Test
    public void testGenerateRequestUrisWithoutForwardSlash() throws NoSuchAlgorithmException {
        ServiceContext serviceContext = new ServiceContext();
        Map<ClaimType,Object> claims = new HashMap<>();
        claims.put(ClaimType.ISSUER, "issuerValue");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("url");
        //Assert.assertTrue(requestUris.equals());
    }
}
