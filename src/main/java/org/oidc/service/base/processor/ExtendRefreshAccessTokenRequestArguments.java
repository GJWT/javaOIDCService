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

package org.oidc.service.base.processor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.oidc.common.MessageType;
import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * This class extends the refresh access token arguments by arguments located from access token and
 * refresh access token responses.
 */
public class ExtendRefreshAccessTokenRequestArguments extends AbstractRequestArgumentProcessor {

  {
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  {
    preParamVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {

    String state = null;
    if (service.getPreConstructorArgs().containsKey("state")) {
      state = (String) service.getPreConstructorArgs().get("state");
    } else if (requestArguments.containsKey("state")) {
      state = (String) requestArguments.get("state");
    } else {
      error.getDetails().add(new ErrorDetails("state", ErrorType.MISSING_REQUIRED_VALUE));
      throw new RequestArgumentProcessingException(error);
    }

    Map<String, Object> args = new HashMap<String, Object>();
    service.getState().extendRequestArgs(args, MessageType.TOKEN_RESPONSE, state,
        new ArrayList<String>(
            service.getRequestMessage().getParameterVerificationDefinitions().keySet()));
    service.getState().extendRequestArgs(args, MessageType.REFRESH_TOKEN_RESPONSE, state,
        new ArrayList<String>(
            service.getRequestMessage().getParameterVerificationDefinitions().keySet()));
    requestArguments.putAll(args);
  }
}