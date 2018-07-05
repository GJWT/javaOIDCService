package org.oidc.service.base;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Key;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.ProviderConfigurationResponse;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.Algorithm;
import org.oidc.common.FileOrUrl;
import org.oidc.common.KeySpecifications;
import org.oidc.common.ValueException;
import org.oidc.service.util.Constants;

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

    @Ignore
    @Test
    public void testImportKeysWithFile() {
        ServiceContext serviceContext = new ServiceContext();
        KeyJar keyJar = new KeyJar();
        KeyBundle keyBundle = new KeyBundle();
        Key key = new Key();
        keyBundle.addKey(key);
        keyJar.addKeyBundle("owner", keyBundle);
        serviceContext.setKeyJar(keyJar);
        Assert.assertTrue(serviceContext.getKeyJar().getKeyBundle().getKeys().size() == 0);
        Map<FileOrUrl,KeySpecifications> keySpecificationsMap = new HashMap<>();
        KeySpecifications keySpecifications = new KeySpecifications("salesforce.key", Algorithm.RS256);
        keySpecificationsMap.put(FileOrUrl.FILE, keySpecifications);
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
        serviceContext.setBaseUrl("www.yahoo.com");
        serviceContext.fileNameFromWebname("webName");
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        serviceContext.setBaseUrl("www.yahoo.com");
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com/1234");
        Assert.assertTrue(fileName.equals("1234"));
    }

    @Test
    public void testFileNameFromWebnameWhereWebNameDoesntStartsWithForwardSlash() throws Exception {
        ServiceContextConfig serviceContextConfig = new ServiceContextConfig.ServiceContextConfigBuilder().setBaseUrl("www.yahoo.com")
                .buildServiceContext();
        ServiceContext serviceContext = new ServiceContext(keyJar, serviceContextConfig);
        serviceContext.setBaseUrl("www.yahoo.com");
        String fileName = serviceContext.fileNameFromWebname("www.yahoo.com:1234");
        Assert.assertTrue(fileName.equals(":1234"));
    }

    @Test
    public void testGenerateRequestUrisWithNullIssuer() throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.setIssuer("issuer");
        serviceContext.setBaseUrl("baseUrl");
        Map<String,Object> claims = new HashMap<>();
        claims.put(Constants.ISSUER, null);
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("/url");
        Assert.assertTrue(requestUris.size() == 1);
        Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
    }

    @Test
    public void testGenerateRequestUrisWithForwardSlash() throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.setIssuer("issuer");
        serviceContext.setBaseUrl("baseUrl");
        Map<String,Object> claims = new HashMap<>();
        claims.put(Constants.ISSUER, "issuer");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("/url");
        Assert.assertTrue(requestUris.size() == 1);
        Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
    }

    /**
     * PCR = ProviderConfigurationResponse
     * @throws NoSuchAlgorithmException
     * @throws InvalidClaimException 
     */
    @Test
    public void testGenerateRequestUrisWithMultipleClaimsForPCR() throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.setIssuer("issuer");
        serviceContext.setBaseUrl("baseUrl");
        Map<String,Object> claims = new HashMap<>();
        claims.put(Constants.ISSUER, Arrays.asList("issuerValue", "issuerValue2"));
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("/url");
        Assert.assertTrue(requestUris.size() == 1);
        Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
    }

    @Test
    public void testGenerateRequestUrisWithoutForwardSlash() throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
        ServiceContext serviceContext = new ServiceContext();
        serviceContext.setIssuer("issuer");
        serviceContext.setBaseUrl("baseUrl");
        Map<String,Object> claims = new HashMap<>();
        claims.put(Constants.ISSUER, "issuer");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        serviceContext.setProviderConfigurationResponse(pcr);
        List<String> requestUris = serviceContext.generateRequestUris("url");
        Assert.assertTrue(requestUris.size() == 1);
        Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
    }
}
