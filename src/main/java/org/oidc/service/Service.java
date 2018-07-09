package org.oidc.service;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Message;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Map;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.service.base.HttpArguments;

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
   * @param requestArguments
   * @return HttpArguments
   */
  HttpArguments getRequestParameters(Map<String, String> requestArguments)
      throws UnsupportedSerializationTypeException, JsonProcessingException,
      MissingRequiredAttributeException, MalformedURLException, WebFingerException, ValueException,
      UnsupportedEncodingException, SerializationException;

  /**
   * This the start of a pipeline that will:
   * 
   * - Deserializes a response into its response message class. - verifies the correctness of the
   * response by running the verify method belonging to the message class used.
   * 
   * @param response
   *          The response, can be either in a JSON or an urlencoded format
   * @param serializationType
   *          which serialization that was used
   * @param stateKey
   *          The key that corresponds to the appropriate State object
   * @return the parsed and to some extent verified response
   **/
  Message parseResponse(String response, SerializationType serializationType, String stateKey)
      throws Exception;

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
   * @param response
   *          The response, can be either in a JSON or an urlencoded format
   * @return the parsed and to some extent verified response
   **/
  Message parseResponse(String response) throws Exception;

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
   * @param response
   *          The response, can be either in a JSON or an urlencoded format
   * @param serializationType
   *          which serialization that was used
   * @return the parsed and to some extent verified response
   **/
  Message parseResponse(String response, SerializationType serializationType) throws Exception;

  /**
   * This method will run after the response has been parsed and verified. It requires response and
   * stateKey in order for the service context to be updated. StateKey is used to fetch and update
   * the appropriate State associated with a specific service. This method may update certain
   * attributes of the service context such as issuer, clientId, or clientSecret.
   * 
   * @param response
   *          The response as a Message instance
   * @param stateKey
   *          The key that corresponds to the appropriate State object
   */
  void updateServiceContext(Message response, String stateKey);

  /**
   * This method will run after the response has been parsed and verified. It requires response in
   * order for the service context to be updated. This method may update certain attributes of the
   * service context such as issuer, clientId, or clientSecret. This method does not require a
   * stateKey since it is used for services that are not expected to store state in the state DB.
   * 
   * @param response
   *          The response as a Message instance
   */
  void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException;
}