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
import org.oidc.common.ValueException;
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

public class AccessToken extends AbstractService {

  public AccessToken(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.ACCESS_TOKEN;
    this.endpointName = EndpointName.TOKEN;
    this.requestMessage = new AccessTokenRequest();
    this.responseMessage = new AccessTokenResponse();
    this.isSynchronous = true;
    this.serializationType = SerializationType.URL_ENCODED;
    this.deserializationType = SerializationType.JSON;
    this.httpMethod = HttpMethod.POST;
    this.expectedResponseClass = AccessTokenResponse.class;
    this.defaultAuthenticationMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

    this.preConstructors = (List<RequestArgumentProcessor>) Arrays
        .asList((RequestArgumentProcessor) new ExtendAccessTokenRequestArguments());

  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (!(responseMessage instanceof AccessTokenResponse)) {
      throw new ValueException("response not instance of AccessTokenResponse");
    }
    if (responseMessage.getClaims().containsKey("expires_in")) {
      responseMessage.getClaims().put("__expires_at", (System.currentTimeMillis() / 1000)
          + (long) responseMessage.getClaims().get("expires_in"));
    }
    getState().storeItem(response, stateKey, MessageType.TOKEN_RESPONSE);
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException {

    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return new AccessTokenRequest(requestArguments);
  }

}
