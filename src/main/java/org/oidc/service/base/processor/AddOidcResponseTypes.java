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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

import com.google.common.collect.ImmutableMap;

public class AddOidcResponseTypes extends AbstractRequestArgumentProcessor {

  {
    paramVerDefs.put("response_types", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    List<String> responseTypes = (List<String>) requestArguments.get("response_types");
    Set<String> grantTypes = new HashSet<>();
    for (String responseType : responseTypes) {
      String sortedType = getSortedResponseType(responseType);
      List<String> grantType = RESPONSE_TYPES_TO_GRANT_TYPES.get(sortedType);
      if (grantType == null) {
        ErrorDetails details = new ErrorDetails("response_types", ErrorType.VALUE_NOT_ALLOWED,
            "No corresponding grant_type cannot be found");
        error.getDetails().add(details);
        return;
      } else {
        grantTypes.addAll(grantType);
      }
    }
    requestArguments.put("grant_types", Arrays.asList(grantTypes.toArray(new String[0])));
  }

  public static final Map<String, List<String>> RESPONSE_TYPES_TO_GRANT_TYPES = ImmutableMap
      .<String, List<String>>builder().put("code", Arrays.asList("authorization_code"))
      .put("id_token", Arrays.asList("implicit")).put("id_token token", Arrays.asList("implicit"))
      .put("code id_token", Arrays.asList("authorization_code", "implicit"))
      .put("code token", Arrays.asList("authorization_code", "implicit"))
      .put("code id_token token", Arrays.asList("authorization_code", "implicit")).build();

  protected String getSortedResponseType(String responseType) {
    List<String> types = Arrays.asList(responseType.split(" "));
    Collections.sort(types);
    StringBuilder stringBuilder = new StringBuilder();
    for (String type : types) {
      stringBuilder.append(type).append(" ");
    }
    return stringBuilder.toString().trim();
  }
}
