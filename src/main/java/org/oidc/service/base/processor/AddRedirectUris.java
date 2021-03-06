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

import java.util.ArrayList;
import java.util.Map;

import org.oidc.msg.Error;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

public class AddRedirectUris extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    if (!requestArguments.containsKey("redirect_uris")) {
      if (service.getServiceContext().getCallBack() != null) {
        requestArguments.put("redirect_uris",
            new ArrayList<String>(service.getServiceContext().getCallBack().values()));
      } else {
        requestArguments.put("redirect_uris", service.getServiceContext().getRedirectUris());
      }
    }
  }

}
