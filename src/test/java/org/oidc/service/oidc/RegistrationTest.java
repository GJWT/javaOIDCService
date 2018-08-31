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

import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;

/**
 * Unit tests for {@link Registration} service.
 */
public class RegistrationTest extends BaseServiceTest<Registration> {

  ServiceContext serviceContext;
  String clientId;
  String endpoint;

  @Before
  public void init() {
    serviceContext = new ServiceContext();
    endpoint = "https://www.example.com/registration";
    service = new Registration(serviceContext, null, null);
    clientId = "mock_rp";
    service.setEndpoint(endpoint);
  }

  @Test
  public void testNoRedirectUris() throws Exception {
    HttpArguments httpArguments = service.getRequestParameters(null);
    RegistrationRequest request = new RegistrationRequest();
    request.fromJson(httpArguments.getBody());
    Assert.assertFalse(request.verify());
  }

  @Test
  public void testHttpParametersNoUrl() throws Exception {
    RegistrationResponse behaviour = new RegistrationResponse();
    service.setEndpoint(null);
    serviceContext.setBehavior(behaviour);
    HttpArguments httpArguments = service.getRequestParameters(null);
    Assert.assertNull(httpArguments.getUrl());
  }

  @Test
  public void testHttpParameters() throws UnsupportedSerializationTypeException, RequestArgumentProcessingException, SerializationException {
    RegistrationResponse behaviour = new RegistrationResponse();
    serviceContext.setBehavior(behaviour);
    HttpArguments httpArguments = service.getRequestParameters(null);
    Assert.assertEquals(endpoint, httpArguments.getUrl());
  }

  @Test
  public void testUpdateContextMinimal()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    service.updateServiceContext(buildMinimalResponse());
    Assert.assertNotNull(serviceContext.getClientId());
    Assert.assertEquals(clientId, serviceContext.getClientId());
    Map<String, Object> claims = ((Registration) service).getResponseMessage().getClaims();
    Assert.assertEquals(3, claims.size());
    assertMinimal(claims);
    Assert.assertEquals("client_secret_basic", claims.get("token_endpoint_auth_method"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testUpdateContextWrongResponseMsgContents()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    RegistrationResponse response = buildMinimalResponse();
    response.addClaim("client_id_issued_at", "should be a Date");
    service.updateServiceContext(response);
  }

  @Test
  public void testUpdateContextSpec()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, DeserializationException {
    service.updateServiceContext(buildSpecExampleResponse());
    Assert.assertNotNull(serviceContext.getClientId());
    Assert.assertEquals("s6BhdRkqt3", serviceContext.getClientId());
    Assert.assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
        serviceContext.getClientSecret());
    Assert.assertEquals(new Date(1577858400000L), serviceContext.getClientSecretExpiresAt());
    Assert.assertEquals("this.is.an.access.token.value.ffx83",
        serviceContext.getRegistrationAccessToken());
  }

  protected void assertMinimal(Map<String, Object> claims) {
    Assert.assertEquals(Arrays.asList("https://rp.example.org"), claims.get("redirect_uris"));
    Assert.assertEquals(clientId, claims.get("client_id"));
  }

  protected RegistrationResponse buildMinimalResponse() {
    RegistrationResponse response = new RegistrationResponse();
    response.addClaim("redirect_uris", Arrays.asList("https://rp.example.org"));
    response.addClaim("client_id", clientId);
    return response;
  }

  protected RegistrationResponse buildSpecExampleResponse() throws InvalidClaimException, DeserializationException {
    String json = "{\n" + "   \"client_id\": \"s6BhdRkqt3\",\n" + "   \"client_secret\":\n"
        + "     \"ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk\",\n"
        + "   \"client_secret_expires_at\": 1577858400,\n" + "   \"registration_access_token\":\n"
        + "     \"this.is.an.access.token.value.ffx83\",\n" + "   \"registration_client_uri\":\n"
        + "     \"https://server.example.com/connect/register?client_id=s6BhdRkqt3\",\n"
        + "   \"token_endpoint_auth_method\":\n" + "     \"client_secret_basic\",\n"
        + "   \"application_type\": \"web\",\n" + "   \"redirect_uris\":\n"
        + "     [\"https://client.example.org/callback\",\n"
        + "      \"https://client.example.org/callback2\"],\n"
        + "   \"client_name\": \"My Example\",\n"
        + "   \"logo_uri\": \"https://client.example.org/logo.png\",\n"
        + "   \"subject_type\": \"pairwise\",\n" + "   \"sector_identifier_uri\":\n"
        + "     \"https://other.example.net/file_of_redirect_uris.json\",\n"
        + "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\n"
        + "   \"userinfo_encrypted_response_alg\": \"RSA1_5\",\n"
        + "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\",\n"
        + "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\n"
        + "   \"request_uris\":\n"
        + "     [\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]\n"
        + "}";
    RegistrationResponse response = new RegistrationResponse();
    response.fromJson(json);
    return response;
  }
}
