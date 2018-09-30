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

package org.oidc.service.base;

import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.util.Constants;

/**
 * A message implementation for the structure of the serialization of {@link ServiceConfig}.
 */
public class ServiceConfigMessage extends AbstractMessage {

  {
    paramVerDefs.put(Constants.SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD,
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put(Constants.SERVICE_CONFIG_KEY_ENDPOINT,
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put(Constants.SERVICE_CONFIG_KEY_HTTP_METHOD,
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put(Constants.SERVICE_CONFIG_KEY_SERIALIZATION_TYPE,
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put(Constants.SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE,
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("pre_construct", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
    paramVerDefs.put("post_construct", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
  }

  public ServiceConfigMessage(Map<String, Object> claims) {
    super(claims);
  }

}
