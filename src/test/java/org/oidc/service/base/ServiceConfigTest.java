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
import org.junit.Test;
import org.oidc.service.util.Constants;

/**
 * Unit tests for {@link ServiceConfig}.
 */
public class ServiceConfigTest {

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPreConstructorsNotExist() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.NotExistingClass");
    ServiceConfig config = new ServiceConfig(properties);
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPreConstructorsNotCompatible() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.ServiceConfig");
    ServiceConfig config = new ServiceConfig(properties);
  }

  @Test
  public void testValidPreConstructorsOne() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(1, config.getPreConstructors().size());
  }

  @Test
  public void testValidPreConstructorsTwo() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference org.oidc.service.base.processor.AddJwksUriOrJwks");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(2, config.getPreConstructors().size());
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPostConstructorsNotExist() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.NotExistingClass");
    ServiceConfig config = new ServiceConfig(properties);
  }

  @Test(expected = InvalidConfigurationPropertyException.class)
  public void testInvalidPostConstructorsNotCompatible() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.ServiceConfig");
    ServiceConfig config = new ServiceConfig(properties);
  }

  @Test
  public void testValidPostConstructorsOne() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(1, config.getPostConstructors().size());
  }

  @Test
  public void testValidPostConstructorsTwo() throws Exception {
    Properties properties = new Properties();
    properties.setProperty(Constants.SERVICE_CONFIG_KEY_POST_CONSTRUCTORS,
        "org.oidc.service.base.processor.AddClientBehaviourPreference org.oidc.service.base.processor.AddJwksUriOrJwks");
    ServiceConfig config = new ServiceConfig(properties);
    Assert.assertEquals(2, config.getPostConstructors().size());
  }

}
