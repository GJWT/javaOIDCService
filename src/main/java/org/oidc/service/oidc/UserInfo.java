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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.ClaimSource;
import org.oidc.msg.oidc.GenericMessage;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.OpenIDSchema;
import org.oidc.msg.oidc.UserInfoRequest;
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

  /**
   * Constructor.
   * 
   * @param serviceContext service context shared by services, must not be null
   * @param state state database, must not be null
   * @param serviceConfig service specific configuration
   *          
   */
  public UserInfo(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    serviceName = ServiceName.USER_INFO;
    endpointName = EndpointName.USER_INFO;
    requestMessage = new UserInfoRequest();
    responseMessage = new OpenIDSchema();
    expectedResponseClass = OpenIDSchema.class;
    isSynchronous = true;
  }
  
  @Override
  protected ServiceConfig getDefaultServiceConfig() {
    ServiceConfig defaultConfig = new ServiceConfig();
    defaultConfig.setDefaultAuthenticationMethod(ClientAuthenticationMethod.BEARER_HEADER);
    defaultConfig.setHttpMethod(HttpMethod.GET);
    defaultConfig.setDeSerializationType(SerializationType.JSON);
    defaultConfig.setPreConstructors((List<RequestArgumentProcessor>) Arrays
        .asList((RequestArgumentProcessor) new ExtendUserInfoRequestArguments()));
    return defaultConfig;
  }

  /** {@inheritDoc} */
  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException {
    state.storeItem(response, stateKey, MessageType.USER_INFO);
  }

  @Override
  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException {
    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return new UserInfoRequest(requestArguments);
  }

  @Override
  public Message prepareMessageForVerification(Message responseMessage) {

    if (!(responseMessage instanceof OpenIDSchema)) {
      return responseMessage;
    }
    OpenIDSchema response = (OpenIDSchema) responseMessage;
    response.setKeyJar(getServiceContext().getKeyJar());
    response.setIssuer(getServiceContext().getIssuer());
    if (getServiceContext().getBehavior() != null
        && getServiceContext().getBehavior().getClaims() != null) {
      response.setSigAlg((String) getServiceContext().getBehavior().getClaims()
          .get("userinfo_signed_response_alg"));
      response.setEncAlg((String) getServiceContext().getBehavior().getClaims()
          .get("userinfo_encrypted_response_alg"));
      response.setEncEnc((String) getServiceContext().getBehavior().getClaims()
          .get("userinfo_encrypted_response_enc"));
    }
    if (getServiceContext().getAllow().get("missing_kid") != null) {
      response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid"));
    }
    return responseMessage;
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey)
      throws DeserializationException, InvalidClaimException {
    Map<String, Object> args = new HashMap<String, Object>();
    getState().multipleExtendRequestArgs(args, stateKey, Arrays.asList("id_token"),
        Arrays.asList(MessageType.AUTHORIZATION_RESPONSE, MessageType.TOKEN_RESPONSE,
            MessageType.REFRESH_TOKEN_RESPONSE));
    if (args.containsKey("id_token")) {
      IDToken idToken = new IDToken();
      // ID Token has already been verified in this stage
      idToken.fromJwt((String) args.get("id_token"), null, null);
      String receivedSub = (String) responseMessage.getClaims().get("sub");
      String expectedSub = (String) idToken.getClaims().get("sub");
      if (!expectedSub.equals(receivedSub)) {
        throw new InvalidClaimException(String
            .format("expected sub value '%s' but got instead '%s'", expectedSub, receivedSub));
      }
    }
    if (!responseMessage.getClaims().containsKey("_claim_sources")
        || !responseMessage.getClaims().containsKey("_claim_names")) {
      return responseMessage;
    }
    @SuppressWarnings("unchecked")
    GenericMessage claimNames = new GenericMessage(((Map<String, Object>)
        responseMessage.getClaims().get("_claim_names")));
    @SuppressWarnings("unchecked")
    GenericMessage claimSources = new GenericMessage(((Map<String, Object>)
        responseMessage.getClaims().get("_claim_sources")));
    for (Entry<String, Object> entry : claimNames.getClaims().entrySet()) {
      String claim = entry.getKey();
      String src = (String) entry.getValue();
      @SuppressWarnings("unchecked")
      ClaimSource claimSource = new ClaimSource(((Map<String, Object>)
          claimSources.getClaims().get(src)));
      if (claimSource.getClaims().containsKey("JWT")) {
        GenericMessage claimSourcesJwt = new GenericMessage();
        claimSourcesJwt.fromJwt((String) claimSource.getClaims().get("JWT"),
            getServiceContext().getKeyJar(), "");
        if (claimSourcesJwt.getClaims().containsKey(src) && !"sub".equals(claim)) {
          responseMessage.getClaims().put(claim, claimSourcesJwt.getClaims().get(src));
        }
      } else if (claimSource.getClaims().containsKey("endpoint")) {
        // TODO: What to do with distributed claims?
      }

    }

    return responseMessage;
  }

}
