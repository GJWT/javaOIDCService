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

package org.oidc.service.base;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.msg.KeyJar;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oidc.ProviderConfigurationResponse;
import org.oidc.service.util.Constants;

public class ServiceContextTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private KeyJar keyJar;

  @Before
  public void setup() throws ImportException {
    keyJar = new KeyJar();
  }
  
  @Test
  public void testGenerateRequestUrisWithForwardSlash()
      throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
    ServiceContext serviceContext = new ServiceContext();
    serviceContext.setIssuer("issuer");
    serviceContext.setBaseUrl("baseUrl");
    ProviderConfigurationResponse pcr = initializeMinimalConfiguration("issuer");
    serviceContext.setProviderConfigurationResponse(pcr);
    List<String> requestUris = serviceContext.generateRequestUris("/url");
    Assert.assertTrue(requestUris.size() == 1);
    Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
  }

  @Test
  public void testGenerateRequestUrisWithoutForwardSlash()
      throws NoSuchAlgorithmException, ValueException, InvalidClaimException {
    ServiceContext serviceContext = new ServiceContext();
    serviceContext.setIssuer("issuer");
    serviceContext.setBaseUrl("baseUrl");
    ProviderConfigurationResponse pcr = initializeMinimalConfiguration("issuer");
    serviceContext.setProviderConfigurationResponse(pcr);
    List<String> requestUris = serviceContext.generateRequestUris("url");
    Assert.assertTrue(requestUris.size() == 1);
    Assert.assertTrue(requestUris.get(0).startsWith("baseUrl/url/"));
  }

  protected ProviderConfigurationResponse initializeMinimalConfiguration(String issuer) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.ISSUER, issuer);
    claims.put("authorization_endpoint", "mockEndpoint");
    claims.put("jwks_uri", "mockUri");
    claims.put("response_types_supported", Arrays.asList("mockType"));
    claims.put("subject_types_supported", Arrays.asList("mockType"));
    claims.put("id_token_signing_alg_values_supported", Arrays.asList("mockValue"));
    return new ProviderConfigurationResponse(claims);

  }
}
