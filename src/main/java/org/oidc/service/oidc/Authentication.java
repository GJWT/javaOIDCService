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

import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.base.processor.AddClientId;
import org.oidc.service.base.processor.AddNonce;
import org.oidc.service.base.processor.AddRequestObject;
import org.oidc.service.base.processor.AddResponseType;
import org.oidc.service.base.processor.AddScope;
import org.oidc.service.base.processor.AddState;
import org.oidc.service.base.processor.PickRedirectUri;
import org.oidc.service.base.processor.StoreAuthenticationRequest;
import org.oidc.service.base.processor.StoreNonce;
import org.oidc.service.data.State;

/**
 * OIDC provider authentication service.
 */
public class Authentication extends AbstractService {

  /**
   * Constructor.
   * 
   * @param serviceContext service context shared by services, must not be null
   * @param state state database, must not be null
   * @param serviceConfig service specific configuration
   *          
   */
  public Authentication(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.AUTHORIZATION;
    this.endpointName = EndpointName.AUTHORIZATION;
    this.requestMessage = new AuthenticationRequest();
    this.responseMessage = new AuthenticationResponse();
    this.isSynchronous = false;
    this.expectedResponseClass = AuthenticationResponse.class;
  }

  @Override
  protected ServiceConfig getDefaultServiceConfig() {
    ServiceConfig defaultConfig = new ServiceConfig();
    defaultConfig.setHttpMethod(HttpMethod.GET);
    defaultConfig.setSerializationType(SerializationType.URL_ENCODED);
    defaultConfig.setDeSerializationType(SerializationType.URL_ENCODED);
    defaultConfig.setPreConstructors((List<RequestArgumentProcessor>) Arrays.asList(
        (RequestArgumentProcessor) new AddClientId(), new AddState(), new PickRedirectUri(),
        new AddResponseType(), new AddScope(), new AddNonce()));
    defaultConfig.setPostConstructors(
        (List<RequestArgumentProcessor>) Arrays.asList((RequestArgumentProcessor) new StoreNonce(),
            new AddRequestObject(), new StoreAuthenticationRequest()));
    return defaultConfig;
  }

  /** {@inheritDoc} */
  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException {
    if (((AuthenticationResponse) response).getVerifiedIdToken() != null) {
      IDToken idToken = ((AuthenticationResponse) response).getVerifiedIdToken();
      if (!stateKey
          .equals(getState().getStateKeyByNonce((String) idToken.getClaims().get("nonce")))) {
        throw new InvalidClaimException(
            String.format("nonce '%s' in the id token is not matching state record '%s'",
                (String) idToken.getClaims().get("nonce"), stateKey));
      }
      getState().storeItem(idToken, stateKey, MessageType.VERIFIED_IDTOKEN);
    }
    if (response.getClaims().containsKey("expires_in")) {
      response.getClaims().put("__expires_at",
          (System.currentTimeMillis() / 1000) + (long) response.getClaims().get("expires_in"));
    }
    getState().storeItem(response, stateKey, MessageType.AUTHORIZATION_RESPONSE);
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException {

    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return new AuthenticationRequest(requestArguments);
  }

  @Override
  public Message prepareMessageForVerification(Message responseMessage) {
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
    if (getServiceContext().getAllow().get("missing_kid") != null) {
      response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid"));
    }
    return responseMessage;
  }

}
