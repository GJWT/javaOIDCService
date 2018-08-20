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

import java.util.List;
import java.util.Map;
import org.oidc.common.MessageType;
import org.oidc.msg.Message;

/**
 * Contract for cache which can be implemented by developers using in-memory or DB.
 * <p>
 * The State cache is a key,value data store. We name the keys stateKey. The values that are bound
 * to the keys have an internal structure that again is key,value based {@link StateRecord} message.
 * </p>
 **/
public interface State {

  /**
   * Gets StateRecord containing all items based off of stateKey.
   * 
   * @param stateKey
   *          the key that identifies the State Record object
   * @return StateRecord connected to a given key, null if not existing.
   **/
  StateRecord getState(String stateKey);

  /**
   * Store a message.
   * 
   * @param message
   *          request or response
   * @param stateKey
   *          the key under which the information is stored in cache
   * @param messageType
   *          type of message which will be used as sub-key
   * @return true if storing succeeded. If there is no record for state or message type and message
   *         mismatch, false is returned.
   **/
  boolean storeItem(Message message, String stateKey, MessageType messageType);

  /**
   * Retrieves message from cache according to message type.
   * 
   * @param stateKey
   *          the key that identifies the State object
   * @param messageType
   *          determines message type
   * @return message returned from cache
   **/
  Message getItem(String stateKey, MessageType messageType);

  /**
   * Gets issuer ID based off of stateKey.
   * 
   * @param stateKey
   *          the key that identifies the State object
   * @return issuer ID is the ID attached to a particular State identified by the stateKey. Null if
   *         not available.
   **/
  String getIssuer(String stateKey);

  /**
   * Add a set of parameters and their value to a set of request args.
   * 
   * @param args
   *          map of claims
   * @param messageType
   *          which request/response is wanted
   * @param stateKey
   *          the key that identifies the State object
   * @param parameters
   *          a list of parameters that will be looked up in the args map as keys (if present) and
   *          modify if need be
   * @return an updated Map with keys from the list of params and values being the values of those
   *         params in the message. If the param does not appear in the item, it will not appear in
   *         the returned dictionary.
   **/
  Map<String, Object> extendRequestArgs(Map<String, Object> args, MessageType messageType,
      String stateKey, List<String> parameters);

  /**
   * Go through a set of items (by their type) and add the attribute-value pair that matches the
   * list of parameters to the arguments. If the same parameter occurs in 2 different items, then
   * the value in the later one will be the one used.
   * 
   * @param args
   *          initial set of arguments
   * @param stateKey
   *          the key that identifies the State object
   * @param parameters
   *          a list of parameters that we're looking for
   * @param messageTypes
   *          a list of message types specifying which messages we are interested in.
   * @return A possibly augmented map of arguments.
   **/
  Map<String, Object> multipleExtendRequestArgs(Map<String, Object> args, String stateKey,
      List<String> parameters, List<MessageType> messageTypes);

  /**
   * Store the connection between a nonce value and a stateKey value. This allows us later in the
   * game to find the state if we have the nonce.
   * 
   * @param nonce
   *          an arbitrary string that can be used only once
   * @param stateKey
   *          the key that identifies the State object
   **/
  void storeStateKeyForNonce(String nonce, String stateKey);

  /**
   * Find the stateKey value by providing the nonce value. Will raise an exception if the nonce
   * value is absent from the state DB
   * 
   * @param nonce
   *          an arbitrary string that can be used only once
   * @return state the state value, null if not found.
   **/
  String getStateKeyByNonce(String nonce);

  /**
   * Makes a new entry StateRecord in the cache, keys it with state parameter, and then returns the
   * stateKey (i.e. state parameter). If state is set to null or is empty, the state value is
   * generated as random 32-character string.
   * 
   * @param issuer
   *          issuer that is bound to State
   * @param state
   *          value of the state parameter used for keying the StateRecord. If null or empty, the
   *          state value is generated.
   * @return stateKey(i.e. state) value keying the newly created StateRecord
   **/
  String createStateRecord(String issuer, String state);
}