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

import java.util.Map;

import org.oidc.common.MessageType;
import org.oidc.msg.Error;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Class stores Authentication request to stateDb.
 */
public class StoreAuthenticationRequest extends AbstractRequestArgumentProcessor {

  {
    paramVerDefs.put("state", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {

    service.getState().storeItem(service.getRequestMessage(),
        (String) requestArguments.get("state"), MessageType.AUTHORIZATION_REQUEST);
  }
}
