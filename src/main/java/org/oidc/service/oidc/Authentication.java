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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.oidc.common.EndpointName;
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
import org.oidc.service.base.processor.AddNonce;
import org.oidc.service.base.processor.AddRequestObject;
import org.oidc.service.base.processor.AddResponseType;
import org.oidc.service.base.processor.AddScope;
import org.oidc.service.base.processor.AddState;
import org.oidc.service.base.processor.PickRedirectUri;
import org.oidc.service.base.processor.StoreAuthenticationRequest;
import org.oidc.service.base.processor.StoreNonce;
import org.oidc.service.data.State;

public class Authentication extends AbstractService {

  public Authentication(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.AUTHORIZATION;
    this.endpointName = EndpointName.AUTHORIZATION;
    this.requestMessage = new AuthenticationRequest();
    this.responseMessage = new AuthenticationResponse();
    this.expectedResponseClass = AuthenticationResponse.class;

    this.preConstructors = (List<RequestArgumentProcessor>) Arrays.asList(new AddState(),
        new PickRedirectUri(), new AddResponseType(), new AddScope(), new AddNonce());
    this.postConstructors = (List<RequestArgumentProcessor>) Arrays.asList(new StoreNonce(),
        new AddRequestObject(), new StoreAuthenticationRequest());
  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    // TODO
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments)
      throws ValueException, MissingRequiredAttributeException, JsonProcessingException,
      UnsupportedSerializationTypeException, SerializationException, InvalidClaimException {

    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws MissingRequiredAttributeException {
    return new AuthenticationRequest(requestArguments);
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey) {
    if (!(responseMessage instanceof AuthenticationResponse)) {
      return responseMessage;
    }
    AuthenticationResponse response = (AuthenticationResponse) responseMessage;
    response.setKeyJar(getServiceContext().getKeyJar());
    response.setIssuer(getServiceContext().getIssuer());
    response.setClientId(getServiceContext().getClientId());
    response.setSkew(getServiceContext().getClockSkew());
    if (getServiceContext().getBehavior() != null
        && getServiceContext().getBehavior().getClaims() != null) {
      response.setSigAlg((String) getServiceContext().getBehavior().getClaims()
          .get("id_token_signed_response_alg"));
      response.setEncAlg((String) getServiceContext().getBehavior().getClaims()
          .get("id_token_encrypted_response_alg"));
      response.setEncEnc((String) getServiceContext().getBehavior().getClaims()
          .get("id_token_encrypted_response_enc"));
    }
    if (getServiceContext().getAllow().containsKey("missing_kid")) {
      response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid"));
    }
    return responseMessage;
  }

}
