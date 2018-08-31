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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerificationDefinition;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;

/**
 * Base class for all {@link RequestArgumentProcessor} implementations.
 */
public abstract class AbstractRequestArgumentProcessor implements RequestArgumentProcessor {

  /** Parameter requirements. */
  protected final Map<String, ParameterVerificationDefinition> paramVerDefs = new HashMap<String, ParameterVerificationDefinition>();

  /** Allowed values for desired parameters. */
  protected final Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();

  @Override
  public void processRequestArguments(Map<String, Object> requestArguments, Service service)
      throws RequestArgumentProcessingException {
    Error error = new Error();
    for (String paramName : paramVerDefs.keySet()) {
      // If parameter is defined as REQUIRED, it must exist.
      if (paramVerDefs.get(paramName).isRequired() && (!requestArguments.containsKey(paramName)
          || requestArguments.get(paramName) == null)) {
        ErrorDetails details = new ErrorDetails(paramName, ErrorType.MISSING_REQUIRED_VALUE);
        error.getDetails().add(details);
      }
      Object value = requestArguments.get(paramName);
      if (value == null) {
        continue;
      }
      // If parameter exists, we verify the type of it and possibly transform it.
      try {
        Object transformed = paramVerDefs.get(paramName).getClaimValidator().validate(value);
        requestArguments.put(paramName, transformed);
      } catch (InvalidClaimException e) {
        ErrorDetails details = new ErrorDetails(paramName, ErrorType.INVALID_VALUE_FORMAT, e);
        error.getDetails().add(details);
      }
    }
    try {
      processVerifiedArguments(requestArguments, service, error);
    } catch (RequestArgumentProcessingException e) {
      error = e.getError();
    }
    if (!error.getDetails().isEmpty()) {
      throw new RequestArgumentProcessingException(error);
    }
  }

  protected abstract void processVerifiedArguments(Map<String, Object> requestArguments,
      Service service, Error error) throws RequestArgumentProcessingException;

}
