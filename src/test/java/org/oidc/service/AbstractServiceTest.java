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
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oauth2.ResponseMessage;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.GenericMessage;
import org.oidc.msg.oidc.OpenIDSchema;
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

  @Test
  public void testsetRequestMessage() {
    GenericMessage message = new GenericMessage();
    service.setRequestMessage(message);
    Assert.assertEquals(message, service.getRequestMessage());
  }

  @Test
  public void testsetSynchronous() {
    service.setSynchronous(true);
    Assert.assertTrue(service.isSynchronous);
    service.setSynchronous(false);
    Assert.assertFalse(service.isSynchronous);
  }

  @Test
  public void testsetServiceName() {
    service.setServiceName(ServiceName.ACCESS_TOKEN);
    Assert.assertEquals(ServiceName.ACCESS_TOKEN, service.getServiceName());
  }

  @Test
  public void testsetSerializationType() {
    service.setSerializationType(SerializationType.JSON);
    Assert.assertEquals(SerializationType.JSON, service.getSerializationType());
  }

  @Test
  public void testsetState() {
    State state = new InMemoryStateImpl();
    service.setState(state);
    Assert.assertEquals(state, service.getState());
  }

  @Test
  public void testsetServiceContext() {
    ServiceContext serviceContext = new ServiceContext();
    service.setServiceContext(serviceContext);
    Assert.assertEquals(serviceContext, service.getServiceContext());
  }

  @Test
  public void testsetServiceConfig() {
    ServiceConfig serviceConfig = new ServiceConfig();
    service.setServiceConfig(serviceConfig);
    Assert.assertEquals(serviceConfig, service.getServiceConfig());
  }

  @Test
  public void testparseResponseJson()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("testclaim", "testvalue");
    service.setDeserializationType(SerializationType.JSON);
    service.setResponseMessage(new ResponseMessage());
    Message parsedMsg = service.parseResponse(msg.toJson(), "stateKey");
    Assert.assertEquals("testvalue", parsedMsg.getClaims().get("testclaim"));
    Assert.assertEquals("addedvalue", parsedMsg.getClaims().get("addedclaim"));
  }

  @Test
  public void testparseResponseError()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("error", "errorvalue");
    service.setDeserializationType(SerializationType.JSON);
    service.setResponseMessage(new ResponseMessage());
    Message parsedMsg = service.parseResponse(msg.toJson(), "stateKey");
    Assert.assertEquals("errorvalue", parsedMsg.getClaims().get("error"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testparseInvalidResponseError()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("error", 5);
    service.setDeserializationType(SerializationType.JSON);
    service.setResponseMessage(new ResponseMessage());
    Message parsedMsg = service.parseResponse(msg.toJson(), "stateKey");
    Assert.assertEquals("errorvalue", parsedMsg.getClaims().get("error"));
  }

  @Test
  public void testparseResponseUrl()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("testclaim", "testvalue");
    service.setDeserializationType(SerializationType.URL_ENCODED);
    service.setResponseMessage(new ResponseMessage());
    Message parsedMsg = service.parseResponse("https://example.com?" + msg.toUrlEncoded(),
        "stateKey");
    Assert.assertEquals("testvalue", parsedMsg.getClaims().get("testclaim"));
    Assert.assertEquals("addedvalue", parsedMsg.getClaims().get("addedclaim"));
  }

  @Test
  public void testparseResponseJWT()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("sub", "joe");
    msg.addClaim("testclaim", "testvalue");
    OpenIDSchema respMsg = new OpenIDSchema();
    respMsg.setSigAlg("none");
    service.setResponseMessage(respMsg);
    service.setDeserializationType(SerializationType.JWT);
    Message parsedMsg = service
        .parseResponse(msg.toJwt(null, "none", null, null, null, null, null, null), "stateKey");
    Assert.assertEquals("testvalue", parsedMsg.getClaims().get("testclaim"));
    Assert.assertEquals("addedvalue", parsedMsg.getClaims().get("addedclaim"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testparseResponseJWTFailVerify()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("testclaim", "testvalue");
    OpenIDSchema respMsg = new OpenIDSchema();
    respMsg.setSigAlg("none");
    service.setResponseMessage(respMsg);
    service.setDeserializationType(SerializationType.JWT);
    Message parsedMsg = service
        .parseResponse(msg.toJwt(null, "none", null, null, null, null, null, null), "stateKey");
  }

  @Test
  public void testparseResponseJWT2()
      throws DeserializationException, InvalidClaimException, SerializationException {
    GenericMessage msg = new GenericMessage();
    msg.addClaim("sub", "joe");
    msg.addClaim("testclaim", "testvalue");
    OpenIDSchema respMsg = new OpenIDSchema();
    respMsg.setSigAlg("none");
    service.setResponseMessage(respMsg);
    // expect JSON but get JWT
    service.setDeserializationType(SerializationType.JSON);
    Message parsedMsg = service
        .parseResponse(msg.toJwt(null, "none", null, null, null, null, null, null), "stateKey");
    Assert.assertEquals("testvalue", parsedMsg.getClaims().get("testclaim"));
    Assert.assertEquals("addedvalue", parsedMsg.getClaims().get("addedclaim"));
  }

  public class MockService extends AbstractService {

    public MockService(ServiceContext serviceContext, State state, ServiceConfig serviceConfig) {
      super(serviceContext, state, serviceConfig);
      responseMessage = new GenericMessage();
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

    public Message postParseResponse(Message responseMessage, String stateKey)
        throws DeserializationException, InvalidClaimException {
      responseMessage.addClaim("addedclaim", "addedvalue");
      return responseMessage;
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
