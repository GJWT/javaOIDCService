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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.RequestArgumentProcessor;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;

/** Tests for {@link AbstractService}. */
public class AbstractServiceTest {

  ServiceContext serviceContext;
  State state;
  ServiceConfig serviceConfig;
  MockService service;

  @Before
  public void setup() {
    serviceContext = new ServiceContext();
    state = new InMemoryStateImpl();
    serviceConfig = new ServiceConfig();
    serviceConfig.setDefaultAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    serviceConfig.setSerializationType(SerializationType.JWT);
    serviceConfig.setDeSerializationType(SerializationType.JWT);
    serviceConfig.setEndpoint("http://example.com/ep1");
    serviceConfig.setHttpMethod(HttpMethod.GET);
    List<RequestArgumentProcessor> postConstruct = new ArrayList<RequestArgumentProcessor>();
    postConstruct.add(new MockRequestArgumentProcessor());
    serviceConfig.setPostConstructors(postConstruct);
    List<RequestArgumentProcessor> preConstruct = new ArrayList<RequestArgumentProcessor>();
    preConstruct.add(new MockRequestArgumentProcessor());
    preConstruct.add(new MockRequestArgumentProcessor());
    serviceConfig.setPreConstructors(preConstruct);
    Map<String, Object> postConstructArgs = new HashMap<String, Object>();
    postConstructArgs.put("key1", "value1");
    serviceConfig.setPostConstructorArgs(postConstructArgs);
    Map<String, Object> preConstructArgs = new HashMap<String, Object>();
    preConstructArgs.put("key2", "value2");
    serviceConfig.setPreConstructorArgs(preConstructArgs);
    Map<String, Object> requestParams = new HashMap<String, Object>();
    requestParams.put("key2", "value2");
    serviceConfig.setRequestParameters(requestParams);
    service = new MockService(serviceContext, state, serviceConfig);
  }

  @Test
  public void testConstructorInitialization() throws UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        service.getDefaultAuthenticationMethod());
    Assert.assertEquals(SerializationType.JWT, service.getSerializationType());
    // TODO: setter and getter of deserializationtype spelled differently, fix
    Assert.assertEquals(SerializationType.JWT, service.getDeserializationType());
    Assert.assertEquals("http://example.com/ep1", service.getEndpoint());
    Assert.assertEquals(HttpMethod.GET, service.getHttpMethod());
    Assert.assertEquals(1, service.getPostConstructors().size());
    Assert.assertEquals(2, service.getPreConstructors().size());
    Assert.assertEquals("value1", service.getPostConstructorArgs().get("key1"));
    Assert.assertEquals("value2", service.getPreConstructorArgs().get("key2"));
    // TODO, test request params are set correctly

  }

  @Test
  public void testConstructorInitializationDefaultServiceConfig() {
    service = new MockService(serviceContext, state, null);
    Assert.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT,
        service.getDefaultAuthenticationMethod());
    Assert.assertEquals(SerializationType.JSON, service.getSerializationType());
    Assert.assertEquals(SerializationType.JSON, service.getDeserializationType());
    Assert.assertEquals("http://example.com/ep2", service.getEndpoint());
    Assert.assertEquals(HttpMethod.POST, service.getHttpMethod());
    Assert.assertEquals(3, service.getPostConstructors().size());
    Assert.assertEquals(4, service.getPreConstructors().size());
    // TODO, test request params are set correctly
    // TODO: post/pre constructor args are not set by constructor from default config
    // furthermore, whether the map may be null or not should be aligned with other maps/lists
  }

  @Test
  public void testsetDefaultAuthenticationMethod() {
    service.setDefaultAuthenticationMethod(ClientAuthenticationMethod.BEARER_HEADER);
    Assert.assertEquals(ClientAuthenticationMethod.BEARER_HEADER,
        service.getDefaultAuthenticationMethod());
  }

  @Test
  public void testsetDeserializationType() {
    service.setDeserializationType(SerializationType.JSON);
    Assert.assertEquals(SerializationType.JSON, service.getDeserializationType());
  }

  @Test
  public void testsetEndpoint() {
    service.setEndpoint("http://example.com");
    Assert.assertEquals("http://example.com", service.getEndpoint());
  }

  @Test
  public void testsetEndpointName() {
    service.setEndpointName(EndpointName.AUTHORIZATION);
    Assert.assertEquals(EndpointName.AUTHORIZATION, service.getEndpointName());
  }

  @Test
  public void testsetExpectedResponseClass() {
    service.setExpectedResponseClass(AuthenticationResponse.class);
    Assert.assertEquals(AuthenticationResponse.class, service.getExpectedResponseClass());
  }

  @Test
  public void testsetHttpMethod() {
    service.setHttpMethod(HttpMethod.POST);
    Assert.assertEquals(HttpMethod.POST, service.getHttpMethod());
  }

  @Test
  public void testsetPostConstructorArgs() {
    Map<String, Object> postConstructorArgs = new HashMap<String, Object>();
    postConstructorArgs.put("testkey", "testvalue");
    service.setPostConstructorArgs(postConstructorArgs);
    Assert.assertEquals("testvalue", service.getPostConstructorArgs().get("testkey"));
  }

  @Test
  public void testsetPreConstructorArgs() {
    Map<String, Object> preConstructorArgs = new HashMap<String, Object>();
    preConstructorArgs.put("testkey", "testvalue");
    service.setPreConstructorArgs(preConstructorArgs);
    Assert.assertEquals("testvalue", service.getPreConstructorArgs().get("testkey"));
  }

  @Test
  public void testsetPostConstructors() {
    List<RequestArgumentProcessor> list = new ArrayList<RequestArgumentProcessor>();
    MockRequestArgumentProcessor processor = new MockRequestArgumentProcessor();
    list.add(processor);
    service.setPostConstructors(list);
    Assert.assertEquals(1, service.getPostConstructors().size());
    Assert.assertTrue(service.getPostConstructors().contains(processor));
  }

  @Test
  public void testsetPreConstructors() {
    List<RequestArgumentProcessor> list = new ArrayList<RequestArgumentProcessor>();
    MockRequestArgumentProcessor processor = new MockRequestArgumentProcessor();
    list.add(processor);
    service.setPreConstructors(list);
    Assert.assertEquals(1, service.getPreConstructors().size());
    Assert.assertTrue(service.getPreConstructors().contains(processor));
  }

  // TODO: rest of the setters

  public class MockService extends AbstractService {

    public MockService(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
      super(serviceContext, state, serviceConfig);
      // TODO Auto-generated constructor stub
    }

    @Override
    protected ServiceConfig getDefaultServiceConfig() {
      ServiceConfig serviceConfig = new ServiceConfig();
      serviceConfig.setDefaultAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
      serviceConfig.setSerializationType(SerializationType.JSON);
      serviceConfig.setDeSerializationType(SerializationType.JSON);
      serviceConfig.setEndpoint("http://example.com/ep2");
      serviceConfig.setHttpMethod(HttpMethod.POST);
      List<RequestArgumentProcessor> postConstruct = new ArrayList<RequestArgumentProcessor>();
      postConstruct.add(new MockRequestArgumentProcessor());
      postConstruct.add(new MockRequestArgumentProcessor());
      postConstruct.add(new MockRequestArgumentProcessor());
      serviceConfig.setPostConstructors(postConstruct);
      List<RequestArgumentProcessor> preConstruct = new ArrayList<RequestArgumentProcessor>();
      preConstruct.add(new MockRequestArgumentProcessor());
      preConstruct.add(new MockRequestArgumentProcessor());
      preConstruct.add(new MockRequestArgumentProcessor());
      preConstruct.add(new MockRequestArgumentProcessor());
      serviceConfig.setPreConstructors(preConstruct);
      Map<String, Object> postConstructArgs = new HashMap<String, Object>();
      postConstructArgs.put("altkey1", "altvalue1");
      serviceConfig.setPostConstructorArgs(postConstructArgs);
      Map<String, Object> requestParams = new HashMap<String, Object>();
      requestParams.put("altkey2", "altvalue2");
      serviceConfig.setRequestParameters(requestParams);
      return serviceConfig;
    }

    @Override
    protected void doUpdateServiceContext(Message response, String stateKey)
        throws MissingRequiredAttributeException, InvalidClaimException {
      // TODO Auto-generated method stub

    }

    @Override
    public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
        Map<String, Object> requestArguments) throws RequestArgumentProcessingException {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    protected Message doConstructRequest(Map<String, Object> requestArguments)
        throws RequestArgumentProcessingException {
      // TODO Auto-generated method stub
      return null;
    }

  }

  public class MockRequestArgumentProcessor implements RequestArgumentProcessor {

    @Override
    public void processRequestArguments(Map<String, Object> requestArguments, Service service)
        throws RequestArgumentProcessingException {

    }

  }

}
