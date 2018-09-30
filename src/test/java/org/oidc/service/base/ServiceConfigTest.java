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

import java.util.Properties;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.SerializationException;
import org.oidc.service.util.Constants;

/**
 * Unit tests for {@link ServiceConfig}.
 */
public class ServiceConfigTest {
  
  Properties properties;
  
  @Before
  public void setup() {
    properties = new Properties();
  }
  
  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPreConstructorsNotExist() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.NotExistingClass");
    new ServiceConfig(properties);
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPreConstructorsNotCompatible() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.ServiceConfig");
    new ServiceConfig(properties);
  }

  @Test
  public void testValidPreConstructorsOne() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(1, config.getPreConstructors().size());
  }

  @Test
  public void testValidPreConstructorsTwo() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference org.oidc.service.base.processor.AddJwksUriOrJwks");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(2, config.getPreConstructors().size());
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPostConstructorsNotExist() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.NotExistingClass");
    new ServiceConfig(properties);
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPostConstructorsNotCompatible() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.ServiceConfig");
    new ServiceConfig(properties);
  }

  @Test
  public void testValidPostConstructorsOne() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(1, config.getPostConstructors().size());
  }

  @Test
  public void testValidPostConstructorsTwo() throws Exception {
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference org.oidc.service.base.processor.AddJwksUriOrJwks");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(2, config.getPostConstructors().size());
  }
  
  @Test
  public void testValidYamlTwoPostConstructors() throws DeserializationException {
    String yaml = "---\n" + 
        "post_constructors:\n" + 
        "- \"org.oidc.service.base.processor.AddClientBehaviourPreference\"\n" + 
        "- \"org.oidc.service.base.processor.AddJwksUriOrJwks\"\n"; 
    ServiceConfig config = ServiceConfig.fromYaml(yaml);
    Assert.assertEquals(2, config.getPostConstructors().size());
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlPostConstructorsString() throws DeserializationException {
    String yaml = "---\n" + 
        "post_constructors: \"org.oidc.service.base.processor.AddClientBehaviourPreference\"";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test
  public void testValidYamlTwoPreConstructors() throws DeserializationException {
    String yaml = "---\n" + 
        "pre_constructors:\n" + 
        "- \"org.oidc.service.base.processor.AddClientBehaviourPreference\"\n" + 
        "- \"org.oidc.service.base.processor.AddJwksUriOrJwks\"\n"; 
    ServiceConfig config = ServiceConfig.fromYaml(yaml);
    Assert.assertEquals(2, config.getPreConstructors().size());
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlPreConstructorsString() throws DeserializationException {
    String yaml = "---\n" + 
        "pre_constructors: \"org.oidc.service.base.processor.AddClientBehaviourPreference\"";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test
  public void testValidFromYaml() throws DeserializationException {
    String yaml= "---\n" + 
        "default_authn_method: \"CLIENT_SECRET_BASIC\"\n" + 
        "deserialization_type: \"JSON\"\n" + 
        "endpoint: \"https://mock.example.org/\"\n" + 
        "http_method: \"GET\"\n" + 
        "serialization_type: \"URL_ENCODED\"\n" + 
        "allow_non_standard_issuer: true\n" + 
        "allow_http: true\n" + 
        "name: WEBFINGER";
    ServiceConfig config = ServiceConfig.fromYaml(yaml);
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, config.getDefaultAuthenticationMethod());
    Assert.assertEquals(SerializationType.JSON, config.getDeSerializationType());
    Assert.assertEquals("https://mock.example.org/", config.getEndpoint());
    Assert.assertEquals(HttpMethod.GET, config.getHttpMethod());
    Assert.assertEquals(SerializationType.URL_ENCODED, config.getSerializationType());
    Assert.assertTrue(config.isShouldAllowHttp());
    Assert.assertTrue(config.isShouldAllowNonStandardIssuer());
    Assert.assertEquals(ServiceName.WEBFINGER, config.getServiceName());
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlAuthMethod() throws DeserializationException {
    String yaml= "---\n" + 
        "default_authn_method: \"CLIENT_SECRET_INVALID\"\n";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlHttpMethod() throws DeserializationException {
    String yaml= "---\n" + 
        "http_method: \"INVALID\"\n";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlSerialization() throws DeserializationException {
    String yaml= "---\n" + 
        "serialization_type: \"INVALID\"\n";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test(expected = DeserializationException.class)
  public void testInvalidYamlDeserialization() throws DeserializationException {
    String yaml= "---\n" + 
        "deserialization_type: \"INVALID\"\n";
    ServiceConfig.fromYaml(yaml);
  }
  
  @Test
  public void testToYaml() throws SerializationException {
    ServiceConfig config = new ServiceConfig();
    config.setDefaultAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    config.setDeSerializationType(SerializationType.JSON);
    config.setEndpoint("https://mock.example.org/");
    config.setHttpMethod(HttpMethod.GET);
    config.setSerializationType(SerializationType.JSON);
    config.setShouldAllowHttp(true);
    config.setShouldAllowNonStandardIssuer(true);
    String yaml = config.toYaml();
    Assert.assertTrue(yaml.contains("default_authn_method: \"CLIENT_SECRET_BASIC\""));
    Assert.assertTrue(yaml.contains("deserialization_type: \"JSON\""));
    Assert.assertTrue(yaml.contains("endpoint: \"https://mock.example.org/\""));
    Assert.assertTrue(yaml.contains("http_method: \"GET\""));
    Assert.assertTrue(yaml.contains("erialization_type: \"JSON\""));
    Assert.assertTrue(yaml.contains("allow_non_standard_issuer: true"));
    Assert.assertTrue(yaml.contains("allow_http: true"));
  }
  
  @Test
  public void testValidFromJson() throws DeserializationException {
    String json= "{" + 
        "\"default_authn_method\": \"CLIENT_SECRET_BASIC\",\n" + 
        "\"deserialization_type\": \"JSON\",\n" + 
        "\"endpoint\": \"https://mock.example.org/\",\n" + 
        "\"http_method\": \"GET\",\n" + 
        "\"serialization_type\": \"URL_ENCODED\",\n" + 
        "\"allow_non_standard_issuer\": true,\n" + 
        "\"allow_http\": true\n }";
    System.out.println(json);
    ServiceConfig config = ServiceConfig.fromJson(json);
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, config.getDefaultAuthenticationMethod());
    Assert.assertEquals(SerializationType.JSON, config.getDeSerializationType());
    Assert.assertEquals("https://mock.example.org/", config.getEndpoint());
    Assert.assertEquals(HttpMethod.GET, config.getHttpMethod());
    Assert.assertEquals(SerializationType.URL_ENCODED, config.getSerializationType());
    Assert.assertTrue(config.isShouldAllowHttp());
    Assert.assertTrue(config.isShouldAllowNonStandardIssuer());
  }
}
