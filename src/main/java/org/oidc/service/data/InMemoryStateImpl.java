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

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.oidc.common.MessageType;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.RefreshAccessTokenRequest;
import org.oidc.msg.oidc.UserInfoRequest;

/** In memory implementation of State database. */
public class InMemoryStateImpl implements State {

  /** Holds state records. */
  private Map<String, StateRecord> records = new HashMap<String, StateRecord>();
  /** Maps nonce values to state values. */
  private Map<String, String> nonceToState = new HashMap<String, String>();

  @Override
  public StateRecord getState(String stateKey) {
    return records.get(stateKey);
  }

  /**
   * Verify message instance is of expected type.
   * 
   * @param message
   *          message instance to verify.
   * @param messageType
   *          The expected type.
   * @return true if message instance is of the expected type.
   */
  private boolean verifyMessageType(Message message, MessageType messageType) {

    return ((MessageType.AUTHORIZATION_REQUEST.equals(messageType)
        && message instanceof AuthenticationRequest)
        || (MessageType.AUTHORIZATION_RESPONSE.equals(messageType)
            && message instanceof AuthenticationResponse)
        || (MessageType.TOKEN_RESPONSE.equals(messageType)
            && message instanceof AccessTokenResponse)
        || (MessageType.REFRESH_TOKEN_REQUEST.equals(messageType)
            && message instanceof RefreshAccessTokenRequest)
        || (MessageType.REFRESH_TOKEN_RESPONSE.equals(messageType)
            && message instanceof AccessTokenResponse)
        || (MessageType.USER_INFO.equals(messageType) && message instanceof UserInfoRequest));
  }

  @Override
  public boolean storeItem(Message message, String stateKey, MessageType messageType) {
    StateRecord record = records.get(stateKey);
    if (record == null || !verifyMessageType(message, messageType)) {
      return false;
    }
    record.getClaims().put(messageType.name(), message);
    return true;
  }

  @Override
  public Message getItem(String stateKey, MessageType messageType) {
    return records.get(stateKey) != null
        ? (Message) records.get(stateKey).getClaims().get(messageType.name())
        : null;
  }

  @Override
  public String getIssuer(String stateKey) {
    return records.get(stateKey) != null ? (String) records.get(stateKey).getClaims().get("iss")
        : null;
  }

  @Override
  public Map<String, Object> extendRequestArgs(Map<String, Object> args, MessageType messageType,
      String stateKey, List<String> parameters) {
    Message item = getItem(stateKey, messageType);
    if (item != null && parameters != null) {
      for (String claimName : parameters) {
        if (item.getClaims().get(claimName) != null) {
          args.put(claimName, item.getClaims().get(claimName));
        }
      }
    }
    return args;
  }

  @Override
  public Map<String, Object> multipleExtendRequestArgs(Map<String, Object> args, String stateKey,
      List<String> parameters, List<MessageType> messageTypes) {
    if (messageTypes != null) {
      for (MessageType msgType : messageTypes) {
        extendRequestArgs(args, msgType, stateKey, parameters);
      }
    }
    return args;
  }

  @Override
  public void storeStateKeyForNonce(String nonce, String stateKey) {
    nonceToState.put(nonce, stateKey);

  }

  @Override
  public String getStateKeyByNonce(String nonce) {
    return nonceToState.get(nonce);
  }

  @Override
  public String createStateRecord(String issuer, String state) {
    if (state == null || state.isEmpty()) {
      byte[] rand = new byte[32];
      new SecureRandom().nextBytes(rand);
      state = Base64.getUrlEncoder().encodeToString(rand);
    }
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("iss", issuer);
    records.put(state, new StateRecord(claims));
    return state;
  }

}
