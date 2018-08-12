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
import org.oidc.service.base.processor.PickRedirectUri;
import org.oidc.service.data.State;

public class Authentication extends AbstractService {

  public Authentication(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.AUTHORIZATION;
    this.endpointName = EndpointName.AUTHORIZATION;
    this.requestMessage = new AuthenticationRequest();
    this.responseMessage = new AuthenticationResponse();
    this.expectedResponseClass = AuthenticationResponse.class;

    this.preConstructors = (List<RequestArgumentProcessor>) Arrays.asList(new PickRedirectUri(),
        new PreConstruct());
    this.postConstructors = new ArrayList<RequestArgumentProcessor>();
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
    Message response = new AuthenticationRequest(requestArguments);
    return response;
  }

  private class PreConstruct implements RequestArgumentProcessor {

    @SuppressWarnings("unchecked")
    @Override
    public void processRequestArguments(Map<String, Object> requestArguments,
        AbstractService service) throws ValueException {
      if (requestArguments == null || service == null || service.getServiceContext() == null) {
        return;
      }
      ServiceContext context = service.getServiceContext();
      // Set response type, default is code if not otherwise defined.
      // TODO: Do we want to verify the type of the claim first?
      String responseType = (String) requestArguments.get("response_type");
      // TODO: Verify policy for Behavior and it's claims. Can they be null? Assumed here so.
      if (responseType == null && context.getBehavior() != null
          && context.getBehavior().getClaims() != null) {
        if (context.getBehavior().getClaims().containsKey("response_types")) {
          responseType = (String) ((List<String>) context.getBehavior().getClaims()
              .get("response_types")).get(0);
        }
        if (responseType == null) {
          // default response type
          responseType = "code";
        }
        requestArguments.put("response_type", responseType);
      }
      if (!requestArguments.containsKey("scope")) {
        requestArguments.put("scope", "openid");
      }
      // TODO: If there is no value openid in scope, add it. This
      // will mean we need to verify the type of existing unverified scope claim.

      // TODO: Create nonce if needed. The need is checked from response_type argument and the the
      // type of the claims should be verified first.

      // TODO: Python implementation handles here somehow also passing "request_object_signing_alg",
      // "algorithm", "sig_kid" and "request_method" values forward. See how to do it in Java.

    }

  }
}
