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

import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.AccessTokenRequest;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * OIDC provider access token service.
 */
public class AccessToken extends org.oidc.service.oauth2.AccessToken {

  public AccessToken(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.requestMessage = new AccessTokenRequest();
    this.responseMessage = new AccessTokenResponse();
    this.expectedResponseClass = AccessTokenResponse.class;
  }
  
  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (!(responseMessage instanceof AccessTokenResponse)) {
      throw new ValueException("response not instance of AccessTokenResponse");
    }
    if (responseMessage.getClaims().containsKey("id_token")) {
      IDToken idToken = new IDToken();
      try {
        // ID Token has already been verified in this stage
        idToken.fromJwt((String) responseMessage.getClaims().get("id_token"), null, null);
      } catch (DeserializationException e) {
        throw new InvalidClaimException(String.format("Unable to decode id token '%s'",
            (String) responseMessage.getClaims().get("id_token")));
      }
      if (!stateKey
          .equals(getState().getStateKeyByNonce((String) idToken.getClaims().get("nonce")))) {
        throw new ValueException(
            String.format("nonce '%s' in the id token is not matching state record '%s'",
                (String) idToken.getClaims().get("nonce"), stateKey));
      }
    }
    if (responseMessage.getClaims().containsKey("expires_in")) {
      responseMessage.getClaims().put("__expires_at", (System.currentTimeMillis() / 1000)
          + (long) responseMessage.getClaims().get("expires_in"));
    }
    getState().storeItem(response, stateKey, MessageType.TOKEN_RESPONSE);
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey) {
    if (!(responseMessage instanceof AccessTokenResponse)) {
      return responseMessage;
    }
    AccessTokenResponse response = (AccessTokenResponse) responseMessage;
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
  
  @Override
  public ClientAuthenticationMethod getDefaultAuthenticationMethod() {
    if (getServiceContext().getBehavior().getClaims().containsKey("token_endpoint_auth_method")) {
      String method = (String) getServiceContext().getBehavior().getClaims()
          .get("token_endpoint_auth_method");
      return ClientAuthenticationMethod.fromClaimValue(method);
    }
    return defaultAuthenticationMethod;
  }

}
