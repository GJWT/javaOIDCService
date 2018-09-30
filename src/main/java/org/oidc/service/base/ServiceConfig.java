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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.SerializationException;
import org.oidc.service.util.Constants;
import org.oidc.service.util.ServiceUtil;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.common.base.Strings;

/**
 * Configuration that is specific to every service
 */
public class ServiceConfig {

  /**
   * The name for this service.
   */
  private ServiceName serviceName;
  /**
   * A URL defined where this service can be found at the Authorization server
   */
  private String endpoint;
  /**
   * Which client authentication method that should be used for this service if any.
   */
  private ClientAuthenticationMethod defaultAuthenticationMethod;
  /**
   * The HTTP method (POST, GET) that are to be used to transmit the request.
   */
  private HttpMethod httpMethod;
  /**
   * The serialization method to be used on the request before sending
   */
  private SerializationType serializationType;
  /**
   * The deserialization method to be used when deserializing the response
   */
  private SerializationType deSerializationType;
  /**
   * The processors run before message construction.
   */
  protected List<RequestArgumentProcessor> preConstructors;
  /**
   * The processors run after message construction.
   */
  protected List<RequestArgumentProcessor> postConstructors;
  /**
   * The OIDC standard in many places states that you *MUST* use HTTPS and not HTTP. In a number of
   * use cases, that causes a problem. Therefore, the libraries should still be used in those use
   * cases, hence there has to be a way to turn off the default 'only HTTPS is allowed'.
   */
  private boolean shouldAllowHttp;
  /**
   * Allows for nonstandard behavior for schema and issuer
   */
  private boolean shouldAllowNonStandardIssuer;

  public ServiceConfig() {

  }

  public ServiceConfig(String endpoint, ClientAuthenticationMethod defaultAuthenticationMethod,
      HttpMethod httpMethod, SerializationType serializationType,
      SerializationType deSerializationType, boolean shouldAllowHttp,
      boolean shouldAllowNonStandardIssuer) {
    this.endpoint = endpoint;
    this.defaultAuthenticationMethod = defaultAuthenticationMethod;
    this.httpMethod = httpMethod;
    this.serializationType = serializationType;
    this.deSerializationType = deSerializationType;
    this.preConstructors = new ArrayList<>();
    this.postConstructors = new ArrayList<>();
    this.shouldAllowHttp = shouldAllowHttp;
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }

  public ServiceConfig(Properties properties) throws InvalidConfigurationPropertyException {
    this.preConstructors = getProcessorsFromProperty(
        properties.getProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS));
    this.postConstructors = getProcessorsFromProperty(
        properties.getProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS));
  }

  protected List<RequestArgumentProcessor> getProcessorsFromProperty(String spaceSeparated)
      throws InvalidConfigurationPropertyException {
    List<RequestArgumentProcessor> result = new ArrayList<>();
    if (Strings.isNullOrEmpty(spaceSeparated)) {
      return result;
    }
    StringTokenizer tokenizer = new StringTokenizer(spaceSeparated, " ");
    while (tokenizer.hasMoreTokens()) {
      result.add(ServiceUtil.getRequestArgumentProcessor(tokenizer.nextToken()));
    }
    return result;
  }

  public ServiceConfig(boolean shouldAllowHttp, boolean shouldAllowNonStandardIssuer) {
    this.shouldAllowHttp = shouldAllowHttp;
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }

  public ServiceName getServiceName() {
    return serviceName;
  }

  public void setServiceName(ServiceName name) {
    serviceName = name;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
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

  public void setHttpMethod(HttpMethod httpMethod) {
    this.httpMethod = httpMethod;
  }

  public SerializationType getSerializationType() {
    return serializationType;
  }

  public void setSerializationType(SerializationType serializationType) {
    this.serializationType = serializationType;
  }

  public SerializationType getDeSerializationType() {
    return deSerializationType;
  }

  public void setDeSerializationType(SerializationType deSerializationType) {
    this.deSerializationType = deSerializationType;
  }

  public List<RequestArgumentProcessor> getPreConstructors() {
    return preConstructors;
  }

  public void setPreConstructors(List<RequestArgumentProcessor> preConstruct) {
    this.preConstructors = preConstruct;
  }

  public List<RequestArgumentProcessor> getPostConstructors() {
    return postConstructors;
  }

  public void setPostConstructors(List<RequestArgumentProcessor> postConstruct) {
    this.postConstructors = postConstruct;
  }

  public boolean isShouldAllowHttp() {
    return shouldAllowHttp;
  }

  public void setShouldAllowHttp(boolean shouldAllowHttp) {
    this.shouldAllowHttp = shouldAllowHttp;
  }

  public boolean isShouldAllowNonStandardIssuer() {
    return shouldAllowNonStandardIssuer;
  }

  public void setShouldAllowNonStandardIssuer(boolean shouldAllowNonStandardIssuer) {
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }

  public String toYaml() throws SerializationException {
    ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
    SimpleModule module = new SimpleModule();
    module.addSerializer(ServiceConfig.class, new ServiceConfigSerializer());
    mapper.registerModule(module);
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException e) {
      throw new SerializationException("Could not serialize this configuration to YAML", e);
    }
  }

  public static ServiceConfig fromYaml(String yaml) throws DeserializationException {
    return deserialize(new ObjectMapper(new YAMLFactory()), yaml);
  }

  protected static ServiceConfig deserialize(ObjectMapper mapper, String content)
      throws DeserializationException {
    SimpleModule module = new SimpleModule();
    module.addDeserializer(ServiceConfig.class, new ServiceConfigDeserializer());
    mapper.registerModule(module);
    try {
      return mapper.readValue(content, ServiceConfig.class);
    } catch (IOException e) {
      throw new DeserializationException("Could not deserialize the given content to configuration",
          e);
    }
  }

  public static ServiceConfig fromJson(String json) throws DeserializationException {
    Map<String, Object> map = ServiceUtil.parseJsonStringToMap(json);
    ServiceConfigMessage message = new ServiceConfigMessage(map);
    if (!message.verify()) {
      throw new DeserializationException(
          "Invalid contents in the given JSON. " + message.getError().getDetails());
    }
    return deserialize(new ObjectMapper(), json);
  }
}
