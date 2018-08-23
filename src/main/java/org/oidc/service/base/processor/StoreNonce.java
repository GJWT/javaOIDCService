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
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.validator.StringClaimValidator;
import org.oidc.service.AbstractService;
import org.oidc.service.base.RequestArgumentProcessor;

/**
 * Class stores nonce as a key for stateKey in stateDB. If any of the preconditions needed to store
 * the value is not met (as there is no statedn, nonce or state etc). the class fails silently.
 */
public class StoreNonce implements RequestArgumentProcessor {

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, AbstractService service)
      throws ValueException {
    if (requestArguments == null || service == null || service.getState() == null) {
      return;
    }
    try {
      service.getState().storeStateKeyForNonce(
          new StringClaimValidator().validate(requestArguments.get("nonce")),
          new StringClaimValidator().validate(requestArguments.get("state")));
    } catch (InvalidClaimException e) {
      // Indicating exception is not handled on purpose.
      return;
    }
  }
}
