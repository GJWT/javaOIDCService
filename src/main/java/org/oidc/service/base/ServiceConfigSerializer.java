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

import org.oidc.service.util.Constants;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

/**
 * A Jackson serializer for {@link ServiceConfig}.
 */
public class ServiceConfigSerializer extends StdSerializer<ServiceConfig> {

  public ServiceConfigSerializer() {
    this(null);
  }

  public ServiceConfigSerializer(Class<ServiceConfig> t) {
    super(t);
  }

  @Override
  public void serialize(ServiceConfig value, JsonGenerator gen, SerializerProvider provider)
      throws IOException {
    gen.writeStartObject();

    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD,
        value.getDefaultAuthenticationMethod(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE,
        value.getDeSerializationType(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_ENDPOINT, value.getEndpoint(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_HTTP_METHOD, value.getHttpMethod(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_SERIALIZATION_TYPE,
        value.getSerializationType(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_ALLOW_NON_STANDARD_ISSUER,
        value.isShouldAllowNonStandardIssuer(), gen);
    writeObjectIfNotNull(Constants.SERVICE_CONFIG_KEY_SHOULD_ALLOW_HTTP,
        value.isShouldAllowHttp(), gen);

    if (value.getPostConstructors() != null && !value.getPostConstructors().isEmpty()) {
      gen.writeObjectField(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
          getProcessorNames(value.getPostConstructors()));
    }
    if (value.getPreConstructors() != null && !value.getPreConstructors().isEmpty()) {
      gen.writeObjectField(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
          getProcessorNames(value.getPreConstructors()));
    }
    gen.writeEndObject();

  }

  protected List<String> getProcessorNames(List<RequestArgumentProcessor> processors) {
    List<String> names = new ArrayList<>();
    for (RequestArgumentProcessor processor : processors) {
      names.add(processor.getClass().getName().toString());
    }
    return names;
  }

  protected void writeObjectIfNotNull(String fieldName, Object value, JsonGenerator gen)
      throws IOException {
    if (value != null) {
      gen.writeObjectField(fieldName, value);
    }
  }
}
