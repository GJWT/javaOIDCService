package org.oauth2.services;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.ProviderConfigurationResponse;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ParameterException;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;

public class AuthorizationTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    private static final ServiceConfig SERVICE_CONFIG =
            new ServiceConfig(true, true);

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testUpdateServiceContext() throws ParameterException, InvalidClaimException {
        HashMap<String, Object> claims = new HashMap<>();
        String expiresIn = "expiresIn";
        claims.put(expiresIn, 5);
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        Authorization authorization = new Authorization(SERVICE_CONTEXT);
        authorization.updateServiceContext(pcr, "stateKey");
    }

    @Test
    public void testStoreAuthorizationRequest() throws MissingRequiredAttributeException {
        Map<String,String> requestArgs = new HashMap<>();
        requestArgs.put("state", "state");
        Authorization authorization = new Authorization(SERVICE_CONTEXT, SERVICE_CONFIG);
        authorization.storeAuthorizationRequest(requestArgs);
    }

    @Test
    public void getRequestParams() throws JsonProcessingException, SerializationException, UnsupportedSerializationTypeException, WebFingerException, ValueException, MissingRequiredAttributeException, UnsupportedEncodingException, MalformedURLException {
        Map<String,String> requestArgs = new HashMap<>();
        requestArgs.put("foo", "bar");
        requestArgs.put("redirectUri", "https://example.com/cli/authz_cb");
        requestArgs.put("state", "state");
        Authorization authorization = new Authorization(SERVICE_CONTEXT, SERVICE_CONFIG);
        authorization.getRequestParams(requestArgs);
    }

    @Test
    public void testUpdateServiceContextWrongMethod() throws ValueException, MissingRequiredAttributeException {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("StateKey is required in order to update service context");
        Authorization authorization = new Authorization(SERVICE_CONTEXT, SERVICE_CONFIG);
        authorization.updateServiceContext(null);
    }

    @Test
    public void testPostParseResponse() throws InvalidClaimException {
        HashMap<String, Object> claims = new HashMap<>();
        String scope = "scope";
        claims.put(scope, "scope");
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        Authorization authorization = new Authorization(SERVICE_CONTEXT, SERVICE_CONFIG);
        authorization.postParseResponse(pcr);
    }
}
