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
import java.util.regex.Pattern;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.validator.ArrayClaimValidator;
import org.oidc.service.AbstractService;
import org.oidc.service.base.RequestArgumentProcessor;

/**
 * Class ensures scope arguments exists and has values openid. If needed, the scope value is created
 * or manipulated.
 */
public class AddScope implements RequestArgumentProcessor {

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, AbstractService service)
      throws ValueException {
    if (requestArguments == null) {
      return;
    }
    // Manipulate scope. Ensure openid scope is defined.
    if (!requestArguments.containsKey("scope")) {
      requestArguments.put("scope", "openid");
    } else {
      try {
        String spaceSeparatedScopes = new ArrayClaimValidator()
            .validate(requestArguments.get("scope"));
        if (!Pattern.compile("\\bopenid\\b").matcher(spaceSeparatedScopes).find()) {
          spaceSeparatedScopes += spaceSeparatedScopes.length() > 0 ? " openid" : "openid";
          requestArguments.put("scope", spaceSeparatedScopes);
        }
      } catch (InvalidClaimException e) {
        throw new ValueException(
            String.format("Argument scope validation failed '%s'", e.getMessage()));
      }
    }
  }
}