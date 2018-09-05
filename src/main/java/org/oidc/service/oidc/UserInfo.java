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
import java.util.List;
import java.util.Map;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.OpenIDSchema;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.base.processor.ExtendUserInfoRequestArguments;
import org.oidc.service.data.State;

/**
 * OIDC provider userinfo service.
 */
public class UserInfo extends AbstractService {

  public UserInfo(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.USER_INFO;
    this.endpointName = EndpointName.USER_INFO;
    // TODO: Python version has Message as the request message, basically the same as our
    // AbstractMessage.
    // this.requestMessage = new Message();
    this.responseMessage = new OpenIDSchema();
    this.expectedResponseClass = OpenIDSchema.class;
    this.isSynchronous = true;
    this.defaultAuthenticationMethod = ClientAuthenticationMethod.BEARER_HEADER;
    this.httpMethod = HttpMethod.GET;

    // TODO: python implementation ensures state parameter availability for postConstructrors.. bit
    // uncertain if needed.
    this.preConstructors = (List<RequestArgumentProcessor>) Arrays
        .asList((RequestArgumentProcessor) new ExtendUserInfoRequestArguments());

  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    // TODO Auto-generated method stub

  }

  @Override
  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    // TODO The request message construction.
    return null;
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey) {

    if (!(responseMessage instanceof OpenIDSchema)) {
      return responseMessage;
    }
    /**
     * TODO
     */
    return responseMessage;
  }
}
