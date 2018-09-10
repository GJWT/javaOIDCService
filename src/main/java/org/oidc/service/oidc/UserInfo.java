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
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.IDToken;
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
  public Message prepareMessageForVerification(Message responseMessage) {

    if (!(responseMessage instanceof OpenIDSchema)) {
      return responseMessage;
    }
    // TODO: userinfo response needs to be able to deserialize itself from jwt. Add following
    // parameters to openid schema.
    // Then openid schema needs to implement TBD interface with method fromJWT().
    /*
     * OpenIDSchema response = (OpenIDSchema) responseMessage;
     * response.setKeyJar(getServiceContext().getKeyJar());
     * response.setIssuer(getServiceContext().getIssuer());
     * response.setClientId(getServiceContext().getClientId());
     * response.setSkew(getServiceContext().getClockSkew()); if (getServiceContext().getBehavior()
     * != null && getServiceContext().getBehavior().getClaims() != null) {
     * response.setSigAlg((String) getServiceContext().getBehavior().getClaims()
     * .get("userinfo_signed_response_alg")); response.setEncAlg((String)
     * getServiceContext().getBehavior().getClaims() .get("userinfo_encrypted_response_alg"));
     * response.setEncEnc((String) getServiceContext().getBehavior().getClaims()
     * .get("userinfo_encrypted_response_enc")); } if
     * (getServiceContext().getAllow().containsKey("missing_kid")) {
     * response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid")); }
     */
    return responseMessage;
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey)
      throws DeserializationException {
    Map<String, Object> args = new HashMap<String, Object>();
    getState().multipleExtendRequestArgs(args, stateKey, Arrays.asList("id_token"),
        Arrays.asList(MessageType.AUTHORIZATION_RESPONSE, MessageType.TOKEN_RESPONSE,
            MessageType.REFRESH_TOKEN_RESPONSE));
    if (args.containsKey("id_token")) {
      IDToken idToken = new IDToken();
      // ID Token has already been verified in this stage
      idToken.fromJwt((String) responseMessage.getClaims().get("id_token"), null, null);
      String expectedSub = (String) responseMessage.getClaims().get("sub");
      String receivedSub = (String) idToken.getClaims().get("sub");
      if (expectedSub.equals(receivedSub)) {
        throw new DeserializationException(String
            .format("expected sub value '%s' but got instead '%s'", expectedSub, receivedSub));
      }
    } else {
      // TODO: log warning about not being able to verify sub
    }
    // TODO: add handling of distributed claims
    state.storeItem(responseMessage, stateKey, MessageType.USER_INFO);
    return responseMessage;
  }

}
