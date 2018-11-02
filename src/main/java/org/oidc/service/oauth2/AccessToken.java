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

package org.oidc.service.oauth2;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oauth2.AccessTokenRequest;
import org.oidc.msg.oauth2.AccessTokenResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.base.processor.ExtendAccessTokenRequestArguments;
import org.oidc.service.data.State;

/**
 * OAUTH2 provider access token service.
 */
public class AccessToken extends AbstractService {

  public AccessToken(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.ACCESS_TOKEN;
    this.endpointName = EndpointName.TOKEN;
    this.requestMessage = new AccessTokenRequest();
    this.responseMessage = new AccessTokenResponse();
    this.isSynchronous = true;
    this.expectedResponseClass = AccessTokenResponse.class;

    this.preConstructors = (List<RequestArgumentProcessor>) Arrays
        .asList((RequestArgumentProcessor) new ExtendAccessTokenRequestArguments());

  }
  
  @Override
  protected ServiceConfig getDefaultServiceConfig() {
    ServiceConfig defaultConfig = new ServiceConfig();
    defaultConfig.setDefaultAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    defaultConfig.setHttpMethod(HttpMethod.POST);
    defaultConfig.setSerializationType(SerializationType.URL_ENCODED);
    defaultConfig.setDeSerializationType(SerializationType.JSON);
    return defaultConfig;
  }

  /** {@inheritDoc} */
  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException {
    if (responseMessage.getClaims().containsKey("expires_in")) {
      responseMessage.getClaims().put("__expires_at", (System.currentTimeMillis() / 1000)
          + (long) responseMessage.getClaims().get("expires_in"));
    }
    getState().storeItem(response, stateKey, MessageType.TOKEN_RESPONSE);
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException {
    httpArguments.getHeader().setContentType("application/x-www-form-urlencoded");
    String clientId = (String) serviceContext.getBehavior().getClaims().get("client_id");
    String clientSecret = (String) serviceContext.getBehavior().getClaims().get("client_secret");
    String method = (String) serviceContext.getBehavior().getClaims().get("token_endpoint_auth_method");
    if ("client_secret_basic".equals(method)) {
      String authorization = StringUtils.newStringUtf8(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
      httpArguments.getHeader().setAuthorization("Basic " + authorization);
    }
    if ("client_secret_post".equals(method)) {
      String authnParameters = "&client_id=" + clientId + "&client_secret=" + clientSecret;
      httpArguments.setBody(httpArguments.getBody() + authnParameters);
    }
    //TODO: support other client authentication methods
    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return new AccessTokenRequest(requestArguments);
  }
}
