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
import java.util.regex.Pattern;
import org.oidc.msg.DataLocation;
import org.oidc.msg.Error;
import org.oidc.msg.ParameterVerification;
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

  {
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("response_mode", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("response_type",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
  }

  @SuppressWarnings("unchecked")
  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {

    if (requestArguments.containsKey("redirect_uri")) {
      return;
    }
    ServiceContext context = service.getServiceContext();
    if (context.getCallBack() == null) {
      if (context.getRedirectUris() != null && !context.getRedirectUris().isEmpty()) {
        requestArguments.put("redirect_uri", context.getRedirectUris().get(0));
      }
      return;
    }
    if ("form_post".equals(requestArguments.get("response_mode"))) {
      if (context.getCallBack().get(DataLocation.FORM_POST) != null) {
        requestArguments.put("redirect_uri", context.getCallBack().get(DataLocation.FORM_POST));
      }
      return;
    }
    String responseType = (String) requestArguments.get("response_type");
    if (responseType == null && context.getBehavior() != null
        && context.getBehavior().getClaims().containsKey("response_types")) {
      responseType = (String) ((List<String>) context.getBehavior().getClaims()
          .get("response_types")).get(0);
    }
    if (responseType == null) {
      // We resolve the redirect uri by default response type
      responseType = "code";
    }
    if (Pattern.compile("\\bcode\\b").matcher(responseType).find()
        && context.getCallBack().get(DataLocation.QUERY_STRING) != null) {
      requestArguments.put("redirect_uri", context.getCallBack().get(DataLocation.QUERY_STRING));
    } else if (context.getCallBack().get(DataLocation.FRAGMENT) != null) {
      requestArguments.put("redirect_uri", context.getCallBack().get(DataLocation.FRAGMENT));
    }
  }
}