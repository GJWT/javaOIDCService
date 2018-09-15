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

import java.util.List;
import java.util.Map;
import org.oidc.msg.Error;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;

/**
 * Class for adding response_type if not already set in request arguments. If response_type is not
 * already set in request arguments method tries to locate registration data and it's field
 * response_types. If located, response_type receives the index 0 value of response_types. 
 */
public class AddResponseType extends AbstractRequestArgumentProcessor {

  @SuppressWarnings("unchecked")
  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    ServiceContext context = service.getServiceContext();
    if (!requestArguments.containsKey("response_type") && context.getBehavior() != null
        && context.getBehavior().getClaims() != null) {
      String responseType = null;
      if (context.getBehavior().getClaims().containsKey("response_types")) {
        responseType = (String) ((List<String>) context.getBehavior().getClaims()
            .get("response_types")).get(0);
      }
      if (responseType != null) {
        requestArguments.put("response_type", responseType);
      }
    }
  }
}