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
import org.oidc.msg.ParameterVerification;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Class creates a {@link StateRecord} to {@link State} database for state parameter value. If state
 * parameter is not request argument or is of wrong type, state value is created and set as request
 * argument.
 */
public class AddState extends AbstractRequestArgumentProcessor {
  
  {
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    String state = (String) requestArguments.get("state");
    requestArguments.put("state",
        service.getState().createStateRecord(service.getServiceContext().getIssuer(), state));
  }
}