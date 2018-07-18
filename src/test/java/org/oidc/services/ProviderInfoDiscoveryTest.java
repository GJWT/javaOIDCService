package org.oidc.services;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.HashMap;

import org.junit.Assert;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Unit tests for {@link ProviderInfoDiscovery}.
 */
public class ProviderInfoDiscoveryTest {
  
  private static final ServiceContext SERVICE_CONTEXT = new ServiceContext();
  
  @Test
  public void test() throws JsonProcessingException, MalformedURLException, UnsupportedEncodingException, UnsupportedSerializationTypeException, MissingRequiredAttributeException, WebFingerException, ValueException, SerializationException, InvalidClaimException {
    SERVICE_CONTEXT.setIssuer("https://example.com");
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(SERVICE_CONTEXT, null, null);
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals("https://example.com/.well-known/openid-configuration", httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  protected String exampleValidResponse() {
    return "{\n" + 
        "\"version\": \"3.0\",\n" + 
        "\"token_endpoint_auth_methods_supported\": [\n" + 
        "    \"client_secret_post\", \"client_secret_basic\",\n" + 
        "    \"client_secret_jwt\", \"private_key_jwt\"],\n" + 
        "\"claims_parameter_supported\": True,\n" + 
        "\"request_parameter_supported\": True,\n" + 
        "\"request_uri_parameter_supported\": True,\n" + 
        "\"require_request_uri_registration\": True,\n" + 
        "\"grant_types_supported\": [\"authorization_code\",\n" + 
        "                          \"implicit\",\n" + 
        "                          \"urn:ietf:params:oauth:grant-type:jwt-bearer\",\n" + 
        "                          \"refresh_token\"],\n" + 
        "\"response_types_supported\": [\"code\", \"id_token\",\n" + 
        "                             \"id_token token\",\n" + 
        "                             \"code id_token\",\n" + 
        "                             \"code token\",\n" + 
        "                             \"code id_token token\"],\n" + 
        "\"response_modes_supported\": [\"query\", \"fragment\",\n" + 
        "                             \"form_post\"],\n" + 
        "\"subject_types_supported\": [\"public\", \"pairwise\"],\n" + 
        "\"claim_types_supported\": [\"normal\", \"aggregated\",\n" + 
        "                          \"distributed\"],\n" + 
        "\"claims_supported\": [\"birthdate\", \"address\",\n" + 
        "                     \"nickname\", \"picture\", \"website\",\n" + 
        "                     \"email\", \"gender\", \"sub\",\n" + 
        "                     \"phone_number_verified\",\n" + 
        "                     \"given_name\", \"profile\",\n" + 
        "                     \"phone_number\", \"updated_at\",\n" + 
        "                     \"middle_name\", \"name\", \"locale\",\n" + 
        "                     \"email_verified\",\n" + 
        "                     \"preferred_username\", \"zoneinfo\",\n" + 
        "                     \"family_name\"],\n" + 
        "\"scopes_supported\": [\"openid\", \"profile\", \"email\",\n" + 
        "                     \"address\", \"phone\",\n" + 
        "                     \"offline_access\", \"openid\"],\n" + 
        "\"userinfo_signing_alg_values_supported\": [\n" + 
        "    \"RS256\", \"RS384\", \"RS512\",\n" + 
        "    \"ES256\", \"ES384\", \"ES512\",\n" + 
        "    \"HS256\", \"HS384\", \"HS512\",\n" + 
        "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n" + 
        "\"id_token_signing_alg_values_supported\": [\n" + 
        "    \"RS256\", \"RS384\", \"RS512\",\n" + 
        "    \"ES256\", \"ES384\", \"ES512\",\n" + 
        "    \"HS256\", \"HS384\", \"HS512\",\n" + 
        "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n" + 
        "\"request_object_signing_alg_values_supported\": [\n" + 
        "    \"RS256\", \"RS384\", \"RS512\", \"ES256\", \"ES384\",\n" + 
        "    \"ES512\", \"HS256\", \"HS384\", \"HS512\", \"PS256\",\n" + 
        "    \"PS384\", \"PS512\", \"none\"],\n" + 
        "\"token_endpoint_auth_signing_alg_values_supported\": [\n" + 
        "    \"RS256\", \"RS384\", \"RS512\", \"ES256\", \"ES384\",\n" + 
        "    \"ES512\", \"HS256\", \"HS384\", \"HS512\", \"PS256\",\n" + 
        "    \"PS384\", \"PS512\"],\n" + 
        "\"userinfo_encryption_alg_values_supported\": [\n" + 
        "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\",\n" + 
        "    \"A128KW\", \"A192KW\", \"A256KW\",\n" + 
        "    \"ECDH-ES\", \"ECDH-ES+A128KW\", \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n" + 
        "\"id_token_encryption_alg_values_supported\": [\n" + 
        "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\",\n" + 
        "    \"A128KW\", \"A192KW\", \"A256KW\",\n" + 
        "    \"ECDH-ES\", \"ECDH-ES+A128KW\", \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n" + 
        "\"request_object_encryption_alg_values_supported\": [\n" + 
        "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\", \"A128KW\",\n" + 
        "    \"A192KW\", \"A256KW\", \"ECDH-ES\", \"ECDH-ES+A128KW\",\n" + 
        "    \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n" + 
        "\"userinfo_encryption_enc_values_supported\": [\n" + 
        "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n" + 
        "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n" + 
        "\"id_token_encryption_enc_values_supported\": [\n" + 
        "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n" + 
        "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n" + 
        "\"request_object_encryption_enc_values_supported\": [\n" + 
        "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n" + 
        "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n" + 
        "\"acr_values_supported\": [\"PASSWORD\"],\n" + 
        "\"issuer\": \"https://example.com\",\n" + 
        "\"jwks_uri\": \"https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json\",\n" + 
        "\"authorization_endpoint\": \"https://example.com/authorization\",\n" + 
        "\"token_endpoint\": \"https://example.com/token\",\n" + 
        "\"userinfo_endpoint\": \"https://example.com/userinfo\",\n" + 
        "\"registration_endpoint\": \"https://example.com/registration\",\n" + 
        "\"end_session_endpoint\": \"https://example.com/end_session\"}";
  }
}
