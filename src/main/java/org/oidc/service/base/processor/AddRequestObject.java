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
 * Class to add request object to the request if post constructor arguments have a string value of
 * 'request' or 'request_uri' for key 'request_method'. TODO additional arguments. If any of the
 * handled arguments is of wrong type or of unexpected value, processing fails silently.
 * 
 * Class is not usable yet.
 */
public class AddRequestObject implements RequestArgumentProcessor {

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, AbstractService service)
      throws ValueException {
    if (requestArguments == null || service == null) {
      return;
    }
    try {
      String requestMethod = new StringClaimValidator()
          .validate(service.getPostConstructorArgs().get("request_method"));
      if (!"request".equals(requestMethod) || !"request_uri".equals(requestMethod)) {
        return;
      }
      // Resolve algorithm
      String algorithm;
      if (service.getPostConstructorArgs().containsKey("request_object_signing_alg")) {
        algorithm = new StringClaimValidator()
            .validate(service.getPostConstructorArgs().get("request_object_signing_alg"));
      } else {
        if (service.getServiceContext().getBehavior() != null && service.getServiceContext()
            .getBehavior().getClaims().containsKey("request_object_signing_alg")) {
          algorithm = (String) service.getServiceContext().getBehavior().getClaims()
              .get("request_object_signing_alg");

        } else {
          algorithm = "RS256";
        }
      }
      // Resolve keys
      if (!service.getPostConstructorArgs().containsKey("keys")) {
        // Resolve encryption keys
        // Algorithm to keytype
        // kid for args or service context
        // get key from jar
      }
      // verify keytype if from arguments
      // Form request object
      // RO to request arguments or uri handling
    } catch (InvalidClaimException e) {
      // Indicating exception is not handled on purpose.
      return;
    }
  }
}
