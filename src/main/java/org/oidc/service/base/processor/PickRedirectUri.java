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
 * Class for picking redirect uri. If value is defined already in request arguments, nothing is
 * done. If service context has no per response mode / response type call back map defined we use
 * first generally listed redirect uri as the value. If there is per response mode / response type
 * call back map available we apply it in following order. 1) If response_mode is form_post, we use
 * redirect uri value mapped for it. 2) If response_type is code, we use redirect uri value mapped
 * for it. 3) We use redirect uri value mapped for response_type implicit.
 * <p>
 * Class does not fall to any next options if any of the mapped values fails to exist.
 * </p>
 */
public class PickRedirectUri extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    if (requestArguments == null || requestArguments.containsKey("redirect_uri") || service == null
        || service.getServiceContext() == null) {
      return;
    }
    ServiceContext context = service.getServiceContext();
    if (context.getCallBack() == null) {
      if (context.getRedirectUris() != null && context.getRedirectUris().size() > 0) {
        requestArguments.put("redirect_uri", context.getRedirectUris().get(0));
      }
      return;
    }
    if ("form_post".equals(requestArguments.get("response_mode"))) {
      if (context.getCallBack().get("form_post") != null) {
        requestArguments.put("redirect_uri", context.getCallBack().get("form_post"));
      }
      return;
    }
    String responseType = (String) requestArguments.get("response_type");
    // TODO: Verify policy for Behaviour and it's claims. Can they be null? Assumed here so.
    if (responseType == null && context.getBehavior() != null
        && context.getBehavior().getClaims() != null) {
      if (context.getBehavior().getClaims().containsKey("response_types")) {
        responseType = (String) ((List<String>) context.getBehavior().getClaims()
            .get("response_types")).get(0);
      }
    }
    if (responseType == null) {
      // default response type
      responseType = "code";
    }
    if ("code".equals(responseType) && context.getCallBack().get("code") != null) {
      requestArguments.put("redirect_uri", context.getCallBack().get("code"));
    } else if (context.getCallBack().get("implicit") != null) {
      // TODO: Verify this is really the case that everything else defaults to implicit value.
      requestArguments.put("redirect_uri", context.getCallBack().get("implicit"));
    }
  }
}