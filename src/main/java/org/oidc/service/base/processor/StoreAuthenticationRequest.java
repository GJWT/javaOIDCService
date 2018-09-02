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
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.validator.StringClaimValidator;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Class stores Authentication request to stateDb. Class assumes stateDB is available.
 */
public class StoreAuthenticationRequest extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    try {
      String state = new StringClaimValidator().validate(requestArguments.get("state"));
      service.getState().storeItem(service.getRequestMessage(), state,
          MessageType.AUTHORIZATION_REQUEST);
    } catch (InvalidClaimException e) {
      // Indicating exception is not handled on purpose.
      return;
    }
  }
}
