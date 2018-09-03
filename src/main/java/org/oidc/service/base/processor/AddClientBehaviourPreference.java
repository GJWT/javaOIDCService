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

import org.oidc.msg.Error;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;

/**
 * Iterates over all the claims that are defined as required or optional for the given
 * {@link Service}'s request message. If they don't exist in the given request arguments, they are
 * added there from either {̛@link ServiceContext#getBehaviour} or
 * {@link ServiceContext#getClientPreferences()}, if they are set in their claims map.
 */
public class AddClientBehaviourPreference extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    for (String key : service.getRequestMessage().getParameterVerificationDefinitions().keySet()) {
      if (requestArguments.containsKey(key)) {
        continue;
      }
      if (service.getServiceContext().getBehavior() != null
          && service.getServiceContext().getBehavior().getClaims().containsKey(key)) {
        requestArguments.put(key, service.getServiceContext().getBehavior().getClaims().get(key));
      } else if (service.getServiceContext().getClientPreferences() != null) {
        requestArguments.put(key,
            service.getServiceContext().getClientPreferences().getClaims().get(key));
      }
    }
  }
}
