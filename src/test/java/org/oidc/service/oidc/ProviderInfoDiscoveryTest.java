/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.service.oidc;

import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.ProviderConfigurationResponse;
import org.oidc.msg.RegistrationRequest;
import org.oidc.msg.SerializationException;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceContext;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Unit tests for {@link ProviderInfoDiscovery}.
 */
public class ProviderInfoDiscoveryTest {

  ServiceContext serviceContext;
  String issuer;

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    issuer = "https://www.example.com";
    serviceContext.setIssuer(issuer);
  }

  @Test
  public void testHttpParameters() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    HttpArguments httpArguments = service.getRequestParameters(new HashMap<String, String>());
    Assert.assertEquals(issuer + "/.well-known/openid-configuration", httpArguments.getUrl());
    Assert.assertEquals(HttpMethod.GET, httpArguments.getHttpMethod());
  }

  @Test
  public void test()
      throws JsonProcessingException, MalformedURLException, UnsupportedEncodingException,
      UnsupportedSerializationTypeException, MissingRequiredAttributeException, WebFingerException,
      ValueException, SerializationException, InvalidClaimException, DeserializationException {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    Message message = service.parseResponse(exampleValidResponse());
    service.updateServiceContext((ProviderConfigurationResponse) message);
    Assert.assertNotNull(serviceContext.getBehavior());
  }

  @Test
  public void testMatchingPreferences() throws Exception {
    RegistrationRequest preferences = new RegistrationRequest();

    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);

    Message message = service.parseResponse(exampleValidResponse());
    Assert.assertTrue(message instanceof ProviderConfigurationResponse);
    ProviderConfigurationResponse pcr = (ProviderConfigurationResponse) message;

    for (Entry<String, String> entry : ProviderInfoDiscovery.PREFERENCE_TO_PROVIDER.entrySet()) {
      preferences.addClaim(entry.getKey(), pcr.getClaims().get(entry.getValue()));
    }
    serviceContext.setClientPreferences(preferences);
    service.updateServiceContext(pcr);
    for (Entry<String, String> entry : ProviderInfoDiscovery.PREFERENCE_TO_PROVIDER.entrySet()) {
      Assert.assertEquals(serviceContext.getBehavior().getClaims().get(entry.getKey()),
          pcr.getClaims().get(entry.getValue()));
    }
  }

  @Test(expected = MissingRequiredAttributeException.class)
  public void testPreferenceNotSatisfied() throws Exception {
    RegistrationRequest preferences = new RegistrationRequest();

    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);

    Message message = service.parseResponse(exampleValidResponse());
    Assert.assertTrue(message instanceof ProviderConfigurationResponse);
    ProviderConfigurationResponse pcr = (ProviderConfigurationResponse) message;

    preferences.addClaim("request_object_signing_alg", Arrays.asList("CUSTOM_NOT_SUPPORTED"));
    serviceContext.setClientPreferences(preferences);
    service.updateServiceContext(pcr);
  }

  @Test
  public void testCustomPreferences() throws Exception {
    RegistrationRequest preferences = new RegistrationRequest();

    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);

    Message message = service.parseResponse(exampleValidResponse());
    Assert.assertTrue(message instanceof ProviderConfigurationResponse);
    ProviderConfigurationResponse pcr = (ProviderConfigurationResponse) message;
    // try both single String..
    preferences.addClaim("request_object_signing_alg", "RS512");
    // ..and arrays of String values
    preferences.addClaim("request_object_encryption_alg",
        Arrays.asList("RSA-OAEP", "RSA-OAEP-256"));
    preferences.addClaim("request_object_encryption_enc", "A256CBC-HS512");
    preferences.addClaim("userinfo_signed_response_alg", "RS512");
    preferences.addClaim("userinfo_encrypted_response_alg", "RSA-OAEP");
    preferences.addClaim("userinfo_encrypted_response_enc", "A256CBC-HS512");
    preferences.addClaim("id_token_signed_response_alg", "RS512");
    preferences.addClaim("id_token_encrypted_response_alg", "RSA-OAEP");
    preferences.addClaim("id_token_encrypted_response_enc", "A256CBC-HS512");
    preferences.addClaim("default_acr_values", "PASSWORD");
    preferences.addClaim("subject_type", "pairwise");
    // leave empty on purpose and check later it doesn't exist in behaviour
    preferences.addClaim("token_endpoint_auth_method", "");
    preferences.addClaim("token_endpoint_auth_signing_alg", "RS512");
    preferences.addClaim("response_types", "id_token");
    serviceContext.setClientPreferences(preferences);
    service.updateServiceContext(pcr);
    for (Entry<String, Object> entry : serviceContext.getClientPreferences().getClaims()
        .entrySet()) {
      if (!ProviderInfoDiscovery.nullOrEmpty(entry.getValue())) {
        Object behaviourValue = serviceContext.getBehavior().getClaims().get(entry.getKey());
        Object preferredValue = entry.getValue();
        Assert.assertEquals(behaviourValue instanceof List && !(preferredValue instanceof List)
            ? Arrays.asList(entry.getValue())
            : entry.getValue(), behaviourValue);
      }
    }
    Assert.assertNull(serviceContext.getBehavior().getClaims().get("token_endpoint_auth_method"));
  }

  public void testDefaults() throws Exception {
    ProviderInfoDiscovery service = new ProviderInfoDiscovery(serviceContext, null, null);
    Message message = service.parseResponse(minimalValidResponse());
    Assert.assertTrue(message instanceof ProviderConfigurationResponse);
    ProviderConfigurationResponse pcr = (ProviderConfigurationResponse) message;
    service.updateServiceContext(pcr);
    Assert.assertEquals(ProviderInfoDiscovery.PROVIDER_DEFAULT.get("token_endpoint_auth_method"),
        serviceContext.getBehavior().getClaims().get("token_endpoint_auth_method"));
    Assert.assertEquals(ProviderInfoDiscovery.PROVIDER_DEFAULT.get("id_token_signed_response_alg"),
        serviceContext.getBehavior().getClaims().get("id_token_signed_response_alg"));
  }

  protected String exampleValidResponse() {
    return "{\n" + "\"version\": \"3.0\",\n" + "\"token_endpoint_auth_methods_supported\": [\n"
        + "    \"client_secret_post\", \"client_secret_basic\",\n"
        + "    \"client_secret_jwt\", \"private_key_jwt\"],\n"
        + "\"claims_parameter_supported\": true,\n" + "\"request_parameter_supported\": true,\n"
        + "\"request_uri_parameter_supported\": true,\n"
        + "\"require_request_uri_registration\": true,\n"
        + "\"grant_types_supported\": [\"authorization_code\",\n"
        + "                          \"implicit\",\n"
        + "                          \"urn:ietf:params:oauth:grant-type:jwt-bearer\",\n"
        + "                          \"refresh_token\"],\n"
        + "\"response_types_supported\": [\"code\", \"id_token\",\n"
        + "                             \"id_token token\",\n"
        + "                             \"code id_token\",\n"
        + "                             \"code token\",\n"
        + "                             \"code id_token token\"],\n"
        + "\"response_modes_supported\": [\"query\", \"fragment\",\n"
        + "                             \"form_post\"],\n"
        + "\"subject_types_supported\": [\"public\", \"pairwise\"],\n"
        + "\"claim_types_supported\": [\"normal\", \"aggregated\",\n"
        + "                          \"distributed\"],\n"
        + "\"claims_supported\": [\"birthdate\", \"address\",\n"
        + "                     \"nickname\", \"picture\", \"website\",\n"
        + "                     \"email\", \"gender\", \"sub\",\n"
        + "                     \"phone_number_verified\",\n"
        + "                     \"given_name\", \"profile\",\n"
        + "                     \"phone_number\", \"updated_at\",\n"
        + "                     \"middle_name\", \"name\", \"locale\",\n"
        + "                     \"email_verified\",\n"
        + "                     \"preferred_username\", \"zoneinfo\",\n"
        + "                     \"family_name\"],\n"
        + "\"scopes_supported\": [\"openid\", \"profile\", \"email\",\n"
        + "                     \"address\", \"phone\",\n"
        + "                     \"offline_access\", \"openid\"],\n"
        + "\"userinfo_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\",\n" + "    \"ES256\", \"ES384\", \"ES512\",\n"
        + "    \"HS256\", \"HS384\", \"HS512\",\n"
        + "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n"
        + "\"id_token_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\",\n" + "    \"ES256\", \"ES384\", \"ES512\",\n"
        + "    \"HS256\", \"HS384\", \"HS512\",\n"
        + "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n"
        + "\"request_object_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\", \"ES256\", \"ES384\",\n"
        + "    \"ES512\", \"HS256\", \"HS384\", \"HS512\", \"PS256\",\n"
        + "    \"PS384\", \"PS512\", \"none\"],\n"
        + "\"token_endpoint_auth_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\", \"ES256\", \"ES384\",\n"
        + "    \"ES512\", \"HS256\", \"HS384\", \"HS512\", \"PS256\",\n"
        + "    \"PS384\", \"PS512\"],\n" + "\"userinfo_encryption_alg_values_supported\": [\n"
        + "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\",\n"
        + "    \"A128KW\", \"A192KW\", \"A256KW\",\n"
        + "    \"ECDH-ES\", \"ECDH-ES+A128KW\", \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n"
        + "\"id_token_encryption_alg_values_supported\": [\n"
        + "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\",\n"
        + "    \"A128KW\", \"A192KW\", \"A256KW\",\n"
        + "    \"ECDH-ES\", \"ECDH-ES+A128KW\", \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n"
        + "\"request_object_encryption_alg_values_supported\": [\n"
        + "    \"RSA1_5\", \"RSA-OAEP\", \"RSA-OAEP-256\", \"A128KW\",\n"
        + "    \"A192KW\", \"A256KW\", \"ECDH-ES\", \"ECDH-ES+A128KW\",\n"
        + "    \"ECDH-ES+A192KW\", \"ECDH-ES+A256KW\"],\n"
        + "\"userinfo_encryption_enc_values_supported\": [\n"
        + "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n"
        + "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n"
        + "\"id_token_encryption_enc_values_supported\": [\n"
        + "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n"
        + "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n"
        + "\"request_object_encryption_enc_values_supported\": [\n"
        + "    \"A128CBC-HS256\", \"A192CBC-HS384\", \"A256CBC-HS512\",\n"
        + "    \"A128GCM\", \"A192GCM\", \"A256GCM\"],\n"
        + "\"acr_values_supported\": [\"PASSWORD\"],\n"
        + "\"issuer\": \"https://www.example.com\",\n"
        + "\"jwks_uri\": \"https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json\",\n"
        + "\"authorization_endpoint\": \"https://example.com/authorization\",\n"
        + "\"token_endpoint\": \"https://example.com/token\",\n"
        + "\"userinfo_endpoint\": \"https://example.com/userinfo\",\n"
        + "\"registration_endpoint\": \"https://example.com/registration\",\n"
        + "\"end_session_endpoint\": \"https://example.com/end_session\"}";
  }

  protected String minimalValidResponse() {
    return "{\n" + "\"response_types_supported\": [\"code\", \"id_token\",\n"
        + "                             \"id_token token\",\n"
        + "                             \"code id_token\",\n"
        + "                             \"code token\",\n"
        + "                             \"code id_token token\"],\n"
        + "\"subject_types_supported\": [\"public\", \"pairwise\"],\n"
        + "\"id_token_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\",\n" + "    \"ES256\", \"ES384\", \"ES512\",\n"
        + "    \"HS256\", \"HS384\", \"HS512\",\n"
        + "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n"
        + "\"issuer\": \"https://www.example.com\",\n"
        + "\"jwks_uri\": \"https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json\",\n"
        + "\"authorization_endpoint\": \"https://example.com/authorization\"}";
  }
}
