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
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.RefreshAccessTokenRequest;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * OIDC provider refresh access token service.
 */
public class RefreshAccessToken extends org.oidc.service.oauth2.RefreshAccessToken {

  public RefreshAccessToken(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.requestMessage = new RefreshAccessTokenRequest();
    this.responseMessage = new AccessTokenResponse();
    this.expectedResponseClass = AccessTokenResponse.class;

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
