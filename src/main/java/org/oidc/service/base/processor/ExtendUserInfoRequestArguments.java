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

import java.util.Arrays;
import java.util.Map;
import org.oidc.common.MessageType;
import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * This class locates access_token from refresh token response, token response and authentication
 * response unless set as request argument.
 */
public class ExtendUserInfoRequestArguments extends AbstractRequestArgumentProcessor {

  {
    paramVerDefs.put("access_token", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  {
    preParamVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {

    if (requestArguments.containsKey("access_token")) {
      return;
    }
    if (!service.getPreConstructorArgs().containsKey("state")) {
      ErrorDetails details = new ErrorDetails("state", ErrorType.MISSING_REQUIRED_VALUE);
      error.getDetails().add(details);
      throw new RequestArgumentProcessingException(error);
    }
    service.getState().multipleExtendRequestArgs(requestArguments,
        (String) service.getPreConstructorArgs().get("state"), Arrays.asList("access_token"),
        Arrays.asList(MessageType.AUTHORIZATION_RESPONSE, MessageType.TOKEN_RESPONSE,
            MessageType.REFRESH_TOKEN_RESPONSE));
  }
}