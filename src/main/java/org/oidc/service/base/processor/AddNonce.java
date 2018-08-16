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

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.validator.ArrayClaimValidator;
import org.oidc.service.AbstractService;
import org.oidc.service.base.RequestArgumentProcessor;

/**
 * Class ensures nonce value exists if response_type contains id_token value.
 */
public class AddNonce implements RequestArgumentProcessor {

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, AbstractService service)
      throws ValueException {
    if (requestArguments == null) {
      return;
    }
    if (!requestArguments.containsKey("nonce") && requestArguments.containsKey("response_type")) {
      try {
        String responseType = new ArrayClaimValidator()
            .validate(requestArguments.get("response_type"));
        if (Pattern.compile("\\bid_token\\b").matcher(responseType).find()) {
          // TODO: We do create nonce here. Do we not need to store it for comparison?
          byte[] rand = new byte[32];
          new SecureRandom().nextBytes(rand);
          String nonce = Base64.getUrlEncoder().encodeToString(rand);
          requestArguments.put("nonce", nonce);
        }
      } catch (InvalidClaimException e) {
        throw new ValueException(
            String.format("Argument response_type validation failed '%s'", e.getMessage()));
      }
    }
  }
}