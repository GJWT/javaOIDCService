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

package org.oidc.service;

import java.util.Map;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * Provides the methods that are needed to support any request-response protocol such as OIDC,
 * OAuth2 etc.
 */
public interface Service {

  /**
   * Builds the request message and constructs the HTTP headers.
   * 
   * This is the starting point for a pipeline that will:
   * 
   * - construct the request message - add/remove information to/from the request message in the way
   * a specific client authentication method requires. - gather a set of HTTP headers like
   * Content-type and Authorization. - serialize the request message into the necessary format
   * (JSON, urlencoded, signed JWT)
   * 
   * @param requestArguments The request arguments used for constructing the message.
   * @return The information needed for building the HTTP request to OP.
   * @throws UnsupportedSerializationTypeException If the serialization type is not supported.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   * @throws SerializationException If the request cannot be serialized.
   */
  public HttpArguments getRequestParameters(Map<String, Object> requestArguments)
      throws UnsupportedSerializationTypeException, RequestArgumentProcessingException,
      SerializationException;

  /**
   * This the start of a pipeline that will:
   * 
   * - Deserializes a response into its response message class. - verifies the correctness of the
   * response by running the verify method belonging to the message class used.
   * 
   * @param response The response, can be either in a JSON or an urlencoded format.
   * @param serializationType Which serialization that was used.
   * @param stateKey The key that corresponds to the appropriate State object.
   * @throws DeserializationException If the response cannot be deserialized.
   * @throws InvalidClaimException If the response cannot be verified.
   * @return The parsed and to some extent verified response.
   **/
  public Message parseResponse(String response, SerializationType serializationType, String stateKey)
      throws DeserializationException, InvalidClaimException;

  /**
   * This the start of a pipeline that will:
   * 
   * - Deserializes a response into its response message class. - verifies the correctness of the
   * response by running the verify method belonging to the message class used.
   * 
   * @param response The response, can be either in a JSON or an urlencoded format.
   * @param stateKey The key that corresponds to the appropriate State object.
   * @throws DeserializationException If the response cannot be deserialized.
   * @throws InvalidClaimException If the response cannot be verified.
   * @return The parsed and to some extent verified response.
   **/
  public Message parseResponse(String response, String stateKey)
      throws DeserializationException, InvalidClaimException;
  
  /**
   * This the start of a pipeline that will:
   * 
   * - Deserializes a response into its response message class. - verifies the correctness of the
   * response by running the verify method belonging to the message class used.
   * 
   * This method only takes the String version of the response in order for the response to be
   * parsed. The serialization format will default to the service’s responseBodyType value. This
   * method does not require a stateKey since it is used for services that are not expected to store
   * state in the state DB.
   * 
   * @param response The response, can be either in a JSON or an urlencoded format
   * @throws DeserializationException If the response cannot be deserialized.
   * @throws InvalidClaimException If the response cannot be verified.
   * @return The parsed and to some extent verified response.
   **/
  public Message parseResponse(String response) 
      throws DeserializationException, InvalidClaimException;

  /**
   * This is the start of a pipeline that will:
   * 
   * - Deserializes a response into its response message class. - verifies the correctness of the
   * response by running the verify method belonging to the message class used.
   * 
   * This method takes the String version of the response and the serializationType in order for the
   * response to be parsed. This method does not require a stateKey since it is used for services
   * that are not expected to store state in the state DB.
   * 
   * @param response The response, can be either in a JSON or an urlencoded format.
   * @param serializationType Which serialization that was used.
   * @throws DeserializationException If the response cannot be deserialized.
   * @throws InvalidClaimException If the response cannot be verified.
   * @return The parsed and to some extent verified response.
   **/
  public Message parseResponse(String response, SerializationType serializationType)
      throws DeserializationException, InvalidClaimException;

  /**
   * This method will run after the response has been parsed and verified. It requires response and
   * stateKey in order for the service context to be updated. StateKey is used to fetch and update
   * the appropriate State associated with a specific service. This method may update certain
   * attributes of the service context such as issuer, clientId, or clientSecret.
   *
   * @param response The response as a Message instance.
   * @param stateKey The key that identifies the State object.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the response message is unexpected.
   * @throws InvalidClaimException If the response contains invalid claims.
   **/
  public void updateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException;

  /**
   * This method will run after the response has been parsed and verified. It requires response in
   * order for the service context to be updated. This method may update certain attributes of the
   * service context such as issuer, clientId, or clientSecret. This method does not require a
   * stateKey since it is used for services that are not expected to store state in the state DB.
   *
   * @param response The response as a Message instance
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the response message is unexpected.
   * @throws InvalidClaimException If the response contains invalid claims.
   */
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException;
  
  /**
   * Get the request message for this service.
   * 
   * @return The request message for this service.
   */
  public Message getRequestMessage();

  /**
   * Get the response message for this service.
   * 
   * @return The response message for this service.
   */
  public Message getResponseMessage();

  /**
   * Get the service context attached to this service.
   * 
   * @return The service context attached to this service.
   */
  public ServiceContext getServiceContext();
  
  /**
   * Get the map of arguments sent to the post constructors.
   * 
   * @return The map of arguments sent to the post constructors.
   */
  public Map<String, Object> getPostConstructorArgs();
  
  /**
   * Get the map of arguments sent to the pre constructors.
   * 
   * @return The map of arguments sent to the pre constructors.
   */
  public Map<String, Object> getPreConstructorArgs();
  
  /**
   * Get the state attached to this service.
   * 
   * @return The state attached to this service.
   */
  public State getState();
  
  /**
   * Get the name for this service.
   * 
   * @return The name for this service.
   */
  public ServiceName getServiceName();
}