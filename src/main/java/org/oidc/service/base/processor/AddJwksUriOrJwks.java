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

import com.google.common.base.Strings;

public class AddJwksUriOrJwks extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    if (requestArguments.containsKey("jwks_uri")) {
      if (requestArguments.containsKey("jwks")) {
        requestArguments.remove("jwks");
      }
      return;
    } else if (requestArguments.containsKey("jwks")){
      return;
    }
    if (!Strings.isNullOrEmpty(service.getServiceContext().getJwksUri())) {
      requestArguments.put("jwks_uri", service.getServiceContext().getJwksUri());
    }
  }
}
