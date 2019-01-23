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

package org.oidc.service;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import java.io.IOException;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.GenericMessage;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.testutil.KeyUtil;

/** Tests for {@link AbstractAuthenticatedService}. */
public class AbstractAuthenticatedServiceTest {

  ServiceContext serviceContext;
  MockService service;

  @Before
  public void setup() throws IllegalArgumentException, ImportException, UnknownKeyType, ValueError,
      IOException, JWKException {
    serviceContext = new ServiceContext();
    serviceContext.setBehavior(new RegistrationResponse());
    serviceContext.getBehavior().addClaim("client_id", "clientId");
    serviceContext.getBehavior().addClaim("client_secret", "clientSecret");
    serviceContext.getBehavior().addClaim("token_endpoint_auth_method", "client_secret_basic");
    serviceContext.setKeyJar(KeyUtil.getKeyJarPrv(""));
    serviceContext.getBehavior().addClaim("token_endpoint_auth_signing_alg", "RS256");
    service = new MockService(serviceContext, null, null);
  }

  @Test
  public void testBasic() throws UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {
    HttpArguments httpArguments = new HttpArguments();
    httpArguments = service.finalizeGetRequestParameters(httpArguments, null);
    Assert.assertEquals("Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0",
        httpArguments.getHeader().getAuthorization());
    Assert.assertEquals("application/x-www-form-urlencoded",
        httpArguments.getHeader().getContentType());
  }

  @Test
  public void testPost() throws UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {
    serviceContext.getBehavior().addClaim("token_endpoint_auth_method", "client_secret_post");
    HttpArguments httpArguments = new HttpArguments();
    httpArguments = service.finalizeGetRequestParameters(httpArguments, null);
    Assert.assertTrue(httpArguments.getBody().contains("client_secret=clientSecret"));
    Assert.assertEquals("application/x-www-form-urlencoded",
        httpArguments.getHeader().getContentType());
  }

  @Test
  public void testClientSecretJwt() throws UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {
    serviceContext.getBehavior().addClaim("token_endpoint_auth_method", "client_secret_jwt");
    HttpArguments httpArguments = new HttpArguments();
    httpArguments = service.finalizeGetRequestParameters(httpArguments, null);
    Assert.assertTrue(httpArguments.getBody().contains("client_assertion="));
    Assert.assertEquals("application/x-www-form-urlencoded",
        httpArguments.getHeader().getContentType());
  }

  public class MockService extends AbstractAuthenticatedService {

    public MockService(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
      super(serviceContext, state, serviceConfig);
      responseMessage = new GenericMessage();
    }

    @Override
    protected ServiceConfig getDefaultServiceConfig() {
      ServiceConfig serviceConfig = new ServiceConfig();
      serviceConfig.setDefaultAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
      serviceConfig.setSerializationType(SerializationType.JSON);
      serviceConfig.setDeSerializationType(SerializationType.JSON);
      serviceConfig.setEndpoint("http://example.com/ep2");
      serviceConfig.setHttpMethod(HttpMethod.POST);
      return serviceConfig;
    }

    @Override
    protected void doUpdateServiceContext(Message response, String stateKey)
        throws MissingRequiredAttributeException, InvalidClaimException {
      // TODO Auto-generated method stub

    }

    @Override
    protected Message doConstructRequest(Map<String, Object> requestArguments)
        throws RequestArgumentProcessingException {
      // TODO Auto-generated method stub
      return null;
    }

  }

}
