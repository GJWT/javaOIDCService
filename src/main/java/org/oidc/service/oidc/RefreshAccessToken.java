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

import java.util.Date;

import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.RefreshAccessTokenRequest;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * OIDC provider refresh access token service.
 */
public class RefreshAccessToken extends org.oidc.service.oauth2.RefreshAccessToken {

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
    requestMessage = new RefreshAccessTokenRequest();
    responseMessage = new AccessTokenResponse();
    expectedResponseClass = AccessTokenResponse.class;

  }

  /** {@inheritDoc} */
  @Override
  protected void doUpdateServiceContext(Message responseMessage, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException {
    if (((AccessTokenResponse) responseMessage).getVerifiedIdToken() != null) {
      IDToken idToken = ((AccessTokenResponse) responseMessage).getVerifiedIdToken();
      if (!stateKey
          .equals(getState().getStateKeyByNonce((String) idToken.getClaims().get("nonce")))) {
        throw new InvalidClaimException(
            String.format("nonce '%s' in the id token is not matching state record '%s'",
                (String) idToken.getClaims().get("nonce"), stateKey));
      }
      getState().storeItem(idToken, stateKey, MessageType.VERIFIED_IDTOKEN);
    }
    if (responseMessage.getClaims().containsKey("expires_in")) {
      responseMessage.getClaims().put("__expires_at", (System.currentTimeMillis() / 1000)
          + ((Date) responseMessage.getClaims().get("expires_in")).getTime() / 1000);
    }
    getState().storeItem(responseMessage, stateKey, MessageType.REFRESH_TOKEN_RESPONSE);
  }

  @Override
  public Message prepareMessageForVerification(Message responseMessage) {
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
    if (getServiceContext().getAllow().get("missing_kid") != null) {
      response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid"));
    }
    return responseMessage;
  }

  @Override
  public ClientAuthenticationMethod getDefaultAuthenticationMethod() {
    if (getServiceContext().getBehavior().getClaims().get("token_endpoint_auth_method") != null) {
      String method = (String) getServiceContext().getBehavior().getClaims()
          .get("token_endpoint_auth_method");
      ClientAuthenticationMethod parsedMethod = ClientAuthenticationMethod.fromClaimValue(method);
      // We fallback to default method if value is not valid
      return parsedMethod != null ? parsedMethod : defaultAuthenticationMethod;
    }
    return defaultAuthenticationMethod;
  }
}
