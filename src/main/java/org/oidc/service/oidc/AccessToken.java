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

import org.oidc.msg.Message;
import org.oidc.msg.oidc.AccessTokenRequest;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * only started..
 */
public class AccessToken extends org.oidc.service.oauth2.AccessToken {

  public AccessToken(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.requestMessage = new AccessTokenRequest();
    this.responseMessage = new AccessTokenResponse();
    this.expectedResponseClass = AccessTokenResponse.class;
  }

  @Override
  public Message postParseResponse(Message responseMessage, String stateKey) {
    if (!(responseMessage instanceof AccessTokenResponse)) {
      return responseMessage;
    }
    AccessTokenResponse response = (AccessTokenResponse) responseMessage;
    response.setKeyJar(getServiceContext().getKeyJar());
    // TODO: We need to have following commented out methods in AccessTokenResponse
    // response.setIssuer(getServiceContext().getIssuer());
    // response.setClientId(getServiceContext().getClientId());
    // response.setSkew(getServiceContext().getClockSkew());
    if (getServiceContext().getBehavior() != null
        && getServiceContext().getBehavior().getClaims() != null) {
      // response.setSigAlg((String) getServiceContext().getBehavior().getClaims()
      // .get("id_token_signed_response_alg"));
      // response.setEncAlg((String) getServiceContext().getBehavior().getClaims()
      // .get("id_token_encrypted_response_alg"));
      // response.setEncEnc((String) getServiceContext().getBehavior().getClaims()
      // .get("id_token_encrypted_response_enc"));
    }
    if (getServiceContext().getAllow().containsKey("missing_kid")) {
      // response.setAllowMissingKid(getServiceContext().getAllow().get("missing_kid"));
    }
    return responseMessage;
  }

}
