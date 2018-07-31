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

import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.ArrayList;
import java.util.Map;

import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

public class Authentication extends AbstractService {

  public Authentication(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.AUTHORIZATION;
    this.endpointName = EndpointName.AUTHORIZATION;
    this.requestMessage = new AuthenticationRequest();
    this.responseMessage = new AuthenticationResponse();
    this.expectedResponseClass = AuthenticationResponse.class;

    // TODO : PRECONSTRUCTS & INIT
    /*
     * Set default scope value, this is set if not found in gather_request_args in the base class
     * self.default_request_args = {'scope': ['openid']}
     * 
     * // Preconstruct methods 1) set_state.. get state from "extra args"(?), if not there, from req
     * arqs.. if not there generate 2) see def pick_redirect_uris(request_args=None, service=None,
     * **kwargs): 3) see def oidc_pre_construct(self, request_args=None, **kwargs):
     * 
     * self.pre_construct = [self.set_state, pick_redirect_uris, self.oidc_pre_construct]
     * 
     * //PostConstruct methods 1) def oidc_post_construct(self, req, **kwargs)
     */
    this.preConstructors = new ArrayList<RequestArgumentProcessor>();
    this.postConstructors = new ArrayList<RequestArgumentProcessor>();
  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    //TODO
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments)
      throws ValueException, MissingRequiredAttributeException, JsonProcessingException,
      UnsupportedSerializationTypeException, SerializationException, InvalidClaimException {
    if (HttpMethod.GET.equals(httpArguments.getHttpMethod())) {
      httpArguments.setUrl(getEndpoint());
      //TODO: above is invalid, the message should be encoded to httpArguments.setUrl
      httpArguments.setBody(requestMessage.toUrlEncoded());
    }
    return httpArguments;

  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws MissingRequiredAttributeException {
    Message response = new AuthenticationRequest(requestArguments);
    return response;
  }

}
