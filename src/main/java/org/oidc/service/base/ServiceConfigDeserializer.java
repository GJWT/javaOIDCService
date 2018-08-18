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

import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.SerializationType;
import org.oidc.service.util.Constants;
import org.oidc.service.util.ServiceUtil;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

/**
 * A Jackson deserializer for {@link ServiceConfig}.
 */
public class ServiceConfigDeserializer extends StdDeserializer<ServiceConfig> {

  public ServiceConfigDeserializer() {
    this(null);
  }

  public ServiceConfigDeserializer(Class<?> config) {
    super(config);
  }

  @Override
  public ServiceConfig deserialize(JsonParser jp, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {
    JsonNode node = jp.getCodec().readTree(jp);

    ServiceConfig config = new ServiceConfig();

    if (node.get(Constants.SERVICE_CONFIG_KEY_ENDPOINT) != null) {
      config.setEndpoint(node.get(Constants.SERVICE_CONFIG_KEY_ENDPOINT).asText());
    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD) != null) {
      try {
        config.setDefaultAuthenticationMethod(ClientAuthenticationMethod.valueOf(
            node.get(Constants.SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD).asText()));
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationPropertyException(
            "Invalid value for " + Constants.SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD, e);
      }
    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_ALLOW_NON_STANDARD_ISSUER) != null) {
      config.setShouldAllowNonStandardIssuer(Boolean
          .valueOf(node.get(Constants.SERVICE_CONFIG_KEY_ALLOW_NON_STANDARD_ISSUER).asText()));
    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_SHOULD_ALLOW_HTTP) != null) {
      config.setShouldAllowHttp(
          Boolean.valueOf(node.get(Constants.SERVICE_CONFIG_KEY_SHOULD_ALLOW_HTTP).asText()));
    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_SERIALIZATION_TYPE) != null) {
      try {
        config.setSerializationType(SerializationType
            .valueOf(node.get(Constants.SERVICE_CONFIG_KEY_SERIALIZATION_TYPE).asText()));
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationPropertyException(
            "Invalid value for " + Constants.SERVICE_CONFIG_KEY_SERIALIZATION_TYPE, e);
      }
    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE) != null) {
      try {
        config.setDeSerializationType(SerializationType
            .valueOf(node.get(Constants.SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE).asText()));
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationPropertyException(
            "Invalid value for " + Constants.SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE, e);
      }

    }
    if (node.get(Constants.SERVICE_CONFIG_KEY_HTTP_METHOD) != null) {
      try {
        config.setHttpMethod(
            HttpMethod.valueOf(node.get(Constants.SERVICE_CONFIG_KEY_HTTP_METHOD).asText()));
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationPropertyException(
            "Invalid value for " + Constants.SERVICE_CONFIG_KEY_HTTP_METHOD, e);
      }
    }

    config.setPostConstructors(
        getDeserializedProcessors(node, Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS));
    config.setPreConstructors(
        getDeserializedProcessors(node, Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS));

    return config;
  }

  protected List<RequestArgumentProcessor> getDeserializedProcessors(JsonNode node,
      String fieldName) throws IOException {
    JsonNode processorNames = node.get(fieldName);
    if (processorNames == null) {
      return null;
    }
    if (!processorNames.isArray()) {
      throw new IOException("Unexpected (not an array) node type for " + fieldName);
    }
    List<RequestArgumentProcessor> processors = new ArrayList<>();
    for (int i = 0; i < processorNames.size(); i++) {
      processors.add(ServiceUtil.getRequestArgumentProcessor(processorNames.get(i).asText()));
    }
    return processors;
  }
}
