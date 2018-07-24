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

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.msg.oidc.ProviderConfigurationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceContext;

import com.google.common.base.Strings;

public class AddRequestUri implements RequestArgumentProcessor {

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, AbstractService service)
      throws ValueException {
    ServiceContext context = service.getServiceContext();
    if (!Strings.isNullOrEmpty(context.getRequestsDirectory())) {
      ASConfigurationResponse opConfiguration = context.getProviderConfigurationResponse();
      if (opConfiguration != null && opConfiguration instanceof ProviderConfigurationResponse
          && Boolean.TRUE
              .equals(opConfiguration.getClaims().get("require_request_uri_registration"))) {
        try {
          List<String> uris = context.generateRequestUris(context.getRequestsDirectory());
          requestArguments.put("request_uris", uris);
        } catch (NoSuchAlgorithmException | InvalidClaimException e) {
          new ValueException("Could not generate a request URI", e);
        }
      }
    }
  }
}