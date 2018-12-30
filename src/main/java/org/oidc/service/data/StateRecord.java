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

package org.oidc.service.data;

import java.util.Map;

import org.oidc.common.MessageType;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/** State Record in State dbase implementation. */
public class StateRecord extends AbstractMessage {

  { // Set parameter requirements for state record.
    paramVerDefs.put("iss", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put(MessageType.AUTHORIZATION_REQUEST.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.AUTHORIZATION_RESPONSE.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.TOKEN_RESPONSE.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.REFRESH_TOKEN_REQUEST.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.REFRESH_TOKEN_RESPONSE.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.USER_INFO.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put(MessageType.VERIFIED_IDTOKEN.name(),
        ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
  }

  public StateRecord(Map<String, Object> claims) {
    super(claims);
  }

}
