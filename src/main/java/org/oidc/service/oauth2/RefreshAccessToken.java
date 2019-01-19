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
import org.oidc.msg.oauth2.RefreshAccessTokenRequest;
import org.oidc.service.AbstractAuthenticatedService;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.base.processor.ExtendRefreshAccessTokenRequestArguments;
import org.oidc.service.data.State;

/**
 * OAUTH2 provider refresh access token service.
 */
public class RefreshAccessToken extends AbstractAuthenticatedService {

  /**
   * Constructor.
   * 
   * @param serviceContext service context shared by services, must not be null
   * @param state state database, must not be null
   * @param serviceConfig service specific configuration
   *          
   */
  public RefreshAccessToken(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    serviceName = ServiceName.REFRESH_ACCESS_TOKEN;
    endpointName = EndpointName.TOKEN;
    requestMessage = new RefreshAccessTokenRequest();
    responseMessage = new AccessTokenResponse();
    isSynchronous = true;
    expectedResponseClass = AccessTokenResponse.class;
    preConstructors = (List<RequestArgumentProcessor>) Arrays
        .asList((RequestArgumentProcessor) new ExtendRefreshAccessTokenRequestArguments());
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
    if (response.getClaims().containsKey("expires_in")) {
      response.getClaims().put("__expires_at", (System.currentTimeMillis() / 1000)
          + (long) response.getClaims().get("expires_in"));
    }
    getState().storeItem(response, stateKey, MessageType.TOKEN_RESPONSE);
  }
  
  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return new AccessTokenRequest(requestArguments);
  }
  
}
