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

import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.CryptoMessage;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oauth2.ResponseMessage;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.HttpHeader;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;
import org.oidc.service.util.ServiceUtil;

/**
 * This is the base class for all services and provides default implementation for various methods.
 */
public abstract class AbstractService implements Service {

  /**
   * Message that describes the request.
   */
  protected Message requestMessage;

  /**
   * Message that describes the response.
   */
  protected Message responseMessage;

  /**
   * Message that describes the error response.
   */
  protected Message errorResponseMessage = new ResponseMessage();

  /**
   * Expected class for the successful response message.
   */
  protected Class<? extends Message> expectedResponseClass;

  /**
   * The name used for the endpoint in provider information discovery
   */
  protected EndpointName endpointName;

  /**
   * True if the response will be returned as a direct response to the request. The only exception
   * right now to this is the Authorization request where the response is delivered to the client at
   * some later date. Default is True
   */
  protected boolean isSynchronous = true;

  /**
   * ServiceName - enum (A name of the service. Later when a RP/client is implemented instances of
   * different services are found by using this name. No default)
   */
  protected ServiceName serviceName;

  /**
   * Client authentication method - defined in enum ClientAuthenticationMethod (The client
   * authentication method to use if nothing else is specified. Default is '' which means none.)
   */
  protected ClientAuthenticationMethod defaultAuthenticationMethod = ClientAuthenticationMethod.NONE;

  /**
   * HttpMethod - enum (Which HTTP method to use when sending the request. Default is GET)
   */
  protected HttpMethod httpMethod = HttpMethod.GET;

  /**
   * SerializationType - enum (The serialization method to be used for the request. Default is
   * urlencoded)
   */
  protected SerializationType serializationType = SerializationType.URL_ENCODED;

  /**
   * The deserialization method to use on the response. Default is json
   */
  protected SerializationType deserializationType = SerializationType.JSON;

  /**
   * The actual URL provided in provider information discovery.
   */
  private String endpoint;

  /**
   * Serves as an in-memory cache
   */
  protected State state;

  /**
   * It contains information that a client needs to talk to a server. This is shared by various
   * services.
   */
  protected ServiceContext serviceContext;

  /**
   * The processors run before message construction.
   */
  protected List<RequestArgumentProcessor> preConstructors;

  /**
   * The processors run after message construction.
   */
  protected List<RequestArgumentProcessor> postConstructors;

  /**
   * Arguments for processors run before message construction.
   */
  private Map<String, Object> preConstructorArgs = new HashMap<String, Object>();

  /**
   * Arguments for processors run before message construction.
   */
  private Map<String, Object> postConstructorArgs = new HashMap<String, Object>();

  /**
   * Configuration that is specific to every service Additional configuration arguments that could
   * be used to change default values like ClientAuthenticationMethod or add extra parameters to
   * pre/postConstruct methods.
   */
  protected ServiceConfig serviceConfig;

  /**
   * Constants
   */
  private static final String HTTP_METHOD = "httpMethod";
  private static final String AUTHENTICATION_METHOD = "authenticationMethod";
  /**
   * Open ID connection provider
   */
  protected static final String linkRelationType = Constants.OIDC_ISSUER;

  /**
   * @param serviceContext
   *          It contains information that a client needs to talk to a server. This is shared by
   *          various services.
   * @param state
   *          Serves as an in-memory cache
   * @param serviceConfig
   *          Configuration that is specific to every service
   */
  public AbstractService(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
    this.serviceContext = serviceContext;
    this.state = state;
    this.serviceConfig = serviceConfig;
    if (serviceConfig != null && serviceConfig.getDefaultAuthenticationMethod() != null) {
      this.defaultAuthenticationMethod = serviceConfig.getDefaultAuthenticationMethod();
    } else {
      this.defaultAuthenticationMethod = getDefaultServiceConfig().getDefaultAuthenticationMethod();
    }
    if (serviceConfig != null && serviceConfig.getDeSerializationType() != null) {
      this.deserializationType = serviceConfig.getDeSerializationType();
    } else {
      this.deserializationType = getDefaultServiceConfig().getDeSerializationType();
    }
    if (serviceConfig != null && serviceConfig.getEndpoint() != null) {
      this.endpoint = serviceConfig.getEndpoint();
    } else {
      this.endpoint = getDefaultServiceConfig().getEndpoint();
    }
    if (serviceConfig != null && serviceConfig.getHttpMethod() != null) {
      this.httpMethod = serviceConfig.getHttpMethod();
    } else {
      this.httpMethod = getDefaultServiceConfig().getHttpMethod();
    }
    if (serviceConfig != null && serviceConfig.getPostConstructors() != null) {
      this.postConstructors = serviceConfig.getPostConstructors();
    } else {
      this.postConstructors = getDefaultServiceConfig().getPostConstructors();
    }
    if (serviceConfig != null && serviceConfig.getPreConstructors() != null) {
      this.preConstructors = serviceConfig.getPreConstructors();
    } else {
      this.preConstructors = getDefaultServiceConfig().getPreConstructors();
    }
    if (serviceConfig != null && serviceConfig.getPostConstructorArgs() != null) {
      this.postConstructorArgs = serviceConfig.getPostConstructorArgs();
    }
    if (serviceConfig != null && serviceConfig.getPreConstructorArgs() != null) {
      this.preConstructorArgs = serviceConfig.getPreConstructorArgs();
    }
    if (serviceConfig != null && serviceConfig.getSerializationType() != null) {
      this.serializationType = serviceConfig.getSerializationType();
    } else {
      this.serializationType = getDefaultServiceConfig().getSerializationType();
    }
  }

  protected abstract ServiceConfig getDefaultServiceConfig();

  /** {@inheritDoc} */
  public void updateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (response == null) {
      throw new ValueException("The response message is null");
    }
    if (response instanceof ResponseMessage && response.getClaims().containsKey("error")) {
      this.responseMessage = response;
      throw new ValueException("The response message is an error message");
    }
    if (!this.expectedResponseClass.isInstance(response)) {
      throw new ValueException("Unexpected response message type, not instance of "
          + this.responseMessage.getClass().getName());
    }
    if (!response.verify()) {
      throw new ValueException("The message validation failed: " +
          response.getError().getDetails());
    }
    doUpdateServiceContext(response, stateKey);
  }

  /** {@inheritDoc} */
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    updateServiceContext(response, null);
  }

  /**
   * The extending services must implement this method to update the service context and service
   * state as reflected by the response message. The response message is guaranteed to be expected type.
   * 
   * @param response The response as a Message instance.
   * @param stateKey The key that identifies the State object.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws InvalidClaimException If the response contains invalid claims.
   */
  protected abstract void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException;

  /**
   * {@inheritDoc}
   **/
  public Message parseResponse(String responseBody, SerializationType serializationType,
      String stateKey) throws DeserializationException, InvalidClaimException {
    if (serializationType != null) {
      this.serializationType = serializationType;
    }

    String urlInfo = null;
    if (SerializationType.URL_ENCODED.equals(this.serializationType)) {
      try {
        urlInfo = ServiceUtil.getUrlInfo(responseBody);
      } catch (MalformedURLException e) {
        throw new DeserializationException("Invalid URL", e);
      }
    }

    // TODO: the if else logic does not guarantee successful outcome. This and other things in this
    // abstract class need still tender care.
    responseMessage = prepareMessageForVerification(this.responseMessage);
    try {
      if (SerializationType.URL_ENCODED.equals(this.serializationType)) {
        responseMessage.fromUrlEncoded(urlInfo);
      } else if (SerializationType.JSON.equals(this.serializationType)) {
        responseMessage.fromJson(responseBody);
      } else if (SerializationType.JWT.equals(this.serializationType)
          && responseMessage instanceof CryptoMessage) {
        CryptoMessage msg = (CryptoMessage) responseMessage;
        responseMessage.fromJwt(responseBody, msg.getKeyJar(), msg.getIssuer(),
            msg.getNoKidIssuers(), msg.getAllowMissingKid(), msg.getTrustJku());
      }
    } catch (IOException e) {
      throw new DeserializationException("Could not deserialize the given message", e);
    }
    if (responseMessage == null) {
      throw new DeserializationException("Missing or faulty response");
    }
    try {
      if (responseMessage instanceof ResponseMessage
          && ((ResponseMessage) responseMessage).indicatesErrorResponseMessage()) {
        errorResponseMessage.getClaims().putAll(responseMessage.getClaims());
        errorResponseMessage.verify();
        return errorResponseMessage;
      }
      responseMessage.verify();
    } catch (InvalidClaimException e) {
      throw new DeserializationException(
          String.format("Deserialized message failed to verify '%s'", e.getMessage()));
    }
    return postParseResponse(responseMessage, stateKey);
  }

  /**
   * Prepare message for verification. Each service have their own version of this method.
   * 
   * @param responseMessage
   *          the message for to prepare.
   * @return prepared message.
   */
  public Message prepareMessageForVerification(Message responseMessage) {
    return responseMessage;
  }

  /**
   * This method does post processing of the service response. Each service have their own version
   * of this method.
   * 
   * @param responseMessage
   *          the message for post processing.
   * @param stateKey
   *          to store state.
   * @return post processed response.
   * @throws DeserializationException
   * @throws InvalidClaimException If the message cannot be verified.
   */
  public Message postParseResponse(Message responseMessage, String stateKey)
      throws DeserializationException, InvalidClaimException {
    return responseMessage;
  }

  /**
   * {@inheritDoc}
   **/
  public Message parseResponse(String responseBody) 
      throws DeserializationException, InvalidClaimException {
    return parseResponse(responseBody, this.deserializationType, "");
  }

  /**
   * {@inheritDoc}
   **/
  public Message parseResponse(String responseBody, SerializationType serializationType)
      throws DeserializationException, InvalidClaimException {
    return parseResponse(responseBody, serializationType, "");
  }

  /**
   * {@inheritDoc}
   **/
  public Message parseResponse(String responseBody, String stateKey)
      throws DeserializationException, InvalidClaimException {
    return parseResponse(responseBody, this.deserializationType, stateKey);
  }

  /**
   * Builds the request message and constructs the HTTP headers.
   * <p>
   * This is the starting pont for a pipeline that will:
   * <p>
   * - construct the request message - add/remove information to/from the request message in the way
   * a specific client authentication method requires. - gather a set of HTTP headers like
   * Content-type and Authorization. - serialize the request message into the necessary format
   * (JSON, urlencoded, signed JWT)
   *
   * @param requestArguments
   * @return HttpArguments
   * @throws MissingRequiredAttributeException
   * @throws ValueException
   * @throws UnsupportedSerializationTypeException
   * @throws JsonProcessingException
   * @throws SerializationException
   * @throws InvalidClaimException
   */
  public HttpArguments getRequestParameters(Map<String, Object> requestArguments)
      throws UnsupportedSerializationTypeException, RequestArgumentProcessingException,
      SerializationException {
    if (requestArguments == null) {
      requestArguments = new HashMap<String, Object>();
    }
    if (getEndpoint() == null) {
      setEndpoint(getServiceContext().getEndpoints().get(this.endpointName));
    }
    /*
     * if (Strings.isNullOrEmpty((String) requestArguments.get(AUTHENTICATION_METHOD))) {
     * requestArguments.put(AUTHENTICATION_METHOD, this.defaultAuthenticationMethod.name()); }
     * 
     * if (Strings.isNullOrEmpty((String) requestArguments.get(SERIALIZATION_TYPE))) {
     * requestArguments.put(SERIALIZATION_TYPE, this.serializationType.name()); }
     */

    requestMessage = constructRequest(requestArguments);

    HttpArguments httpArguments = new HttpArguments();
    httpArguments.setHttpMethod(
        requestArguments.containsKey(HTTP_METHOD) ? (HttpMethod) requestArguments.get(HTTP_METHOD)
            : httpMethod);

    SerializationType contentType;
    HttpHeader httpHeader = new HttpHeader();
    if (HttpMethod.POST.equals(httpArguments.getHttpMethod())) {
      if (SerializationType.URL_ENCODED.equals(serializationType)) {
        contentType = SerializationType.URL_ENCODED;
      } else {
        contentType = SerializationType.JSON;
      }

      httpArguments.setBody(ServiceUtil.getHttpBody(requestMessage, contentType));
      httpHeader.setContentType(contentType.name());
      httpArguments.setHeader(httpHeader);
      httpArguments.setUrl(getEndpoint());
    }

    if (HttpMethod.GET.equals(httpArguments.getHttpMethod())) {
      if (getEndpoint() != null) {
        httpArguments.setUrl(getEndpoint() + "?" + requestMessage.toUrlEncoded());
      }
    }

    httpArguments = finalizeGetRequestParameters(httpArguments, requestArguments);
    // TODO: check getUrl() here or leave it to the user?
    return httpArguments;
  }

  public abstract HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments) throws RequestArgumentProcessingException;

  protected Message constructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    if (this.preConstructors != null) {
      for (RequestArgumentProcessor processor : this.preConstructors) {
        processor.processRequestArguments(requestArguments, this);
      }
    }

    // TODO: should we gather other configuration? Python checks service_context, self.conf
    setRequestMessage(doConstructRequest(requestArguments));
    if (this.postConstructors != null) {
      for (RequestArgumentProcessor processor : this.postConstructors) {
        processor.processRequestArguments(getRequestMessage().getClaims(), this);
      }
    }
    return getRequestMessage();
  }

  protected abstract Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException;

  public Message getRequestMessage() {
    return requestMessage;
  }

  public void setRequestMessage(Message requestMessage) {
    this.requestMessage = requestMessage;
  }

  public Message getResponseMessage() {
    return responseMessage;
  }

  public void setResponseMessage(Message responseMessage) {
    this.responseMessage = responseMessage;
  }

  public Class<? extends Message> getExpectedResponseClass() {
    return this.expectedResponseClass;
  }

  public void setExpectedResponseClass(Class<? extends Message> responseClass) {
    this.expectedResponseClass = responseClass;
  }

  public EndpointName getEndpointName() {
    return endpointName;
  }

  public void setEndpointName(EndpointName endpointName) {
    this.endpointName = endpointName;
  }

  public boolean isSynchronous() {
    return isSynchronous;
  }

  public void setSynchronous(boolean synchronous) {
    isSynchronous = synchronous;
  }

  public ServiceName getServiceName() {
    return serviceName;
  }

  public void setServiceName(ServiceName serviceName) {
    this.serviceName = serviceName;
  }

  public ClientAuthenticationMethod getDefaultAuthenticationMethod() {
    return defaultAuthenticationMethod;
  }

  public void setDefaultAuthenticationMethod(
      ClientAuthenticationMethod defaultAuthenticationMethod) {
    this.defaultAuthenticationMethod = defaultAuthenticationMethod;
  }

  public HttpMethod getHttpMethod() {
    return httpMethod;
  }

  public static String getAuthenticationMethod() {
    return AUTHENTICATION_METHOD;
  }

  public void setHttpMethod(HttpMethod httpMethod) {
    this.httpMethod = httpMethod;
  }

  public SerializationType getSerializationType() {
    return serializationType;
  }

  public void setSerializationType(SerializationType serializationType) {
    this.serializationType = serializationType;
  }

  public SerializationType getDeserializationType() {
    return deserializationType;
  }

  public void setDeserializationType(SerializationType deserializationType) {
    this.deserializationType = deserializationType;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
  }

  public State getState() {
    return state;
  }

  public void setState(State state) {
    this.state = state;
  }

  public ServiceContext getServiceContext() {
    return serviceContext;
  }

  public void setServiceContext(ServiceContext serviceContext) {
    this.serviceContext = serviceContext;
  }

  public ServiceConfig getServiceConfig() {
    return serviceConfig;
  }

  public void setServiceConfig(ServiceConfig serviceConfig) {
    this.serviceConfig = serviceConfig;
  }

  /**
   * Get arguments for processors run before message construction. Guaranteed not to be null.
   * 
   * @return Map of arguments.
   */
  public Map<String, Object> getPreConstructorArgs() {
    return preConstructorArgs;
  }

  /**
   * Set arguments for processors run before message construction. Cannot be nullified.
   * 
   * @param preConstructorArgs
   *          Map of arguments.
   */
  public void setPreConstructorArgs(Map<String, Object> preConstructorArgs) {
    if (preConstructorArgs != null) {
      this.preConstructorArgs = preConstructorArgs;
    }
  }

  /**
   * Get arguments for processors run after message construction.
   * 
   * @return Map of arguments.
   */
  public Map<String, Object> getPostConstructorArgs() {
    return postConstructorArgs;
  }

  /**
   * Set arguments for processors run after message construction. Cannot be nullified.
   * 
   * @param postConstructorArgs
   *          Map of arguments.
   */
  public void setPostConstructorArgs(Map<String, Object> postConstructorArgs) {
    if (postConstructorArgs != null) {
      this.postConstructorArgs = postConstructorArgs;
    }
  }

  public List<RequestArgumentProcessor> getPreConstructors() {
    return this.preConstructors;
  }

  public void setPreConstructors(List<RequestArgumentProcessor> processors) {
    this.preConstructors = processors;
  }

  public List<RequestArgumentProcessor> getPostConstructors() {
    return this.postConstructors;
  }

  public void setPostConstructors(List<RequestArgumentProcessor> processors) {
    this.postConstructors = processors;
  }
}