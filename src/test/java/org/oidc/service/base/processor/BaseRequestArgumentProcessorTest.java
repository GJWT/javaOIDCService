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

package org.oidc.service.base.processor;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

/**
 * Base unit tests and helpers for classes implementing {@link RequestArgumentProcessor}.
 *
 * @param <T> The class to be tested.
 */
public abstract class BaseRequestArgumentProcessorTest<T extends AbstractRequestArgumentProcessor> {

  T processor;
  Service service;
  
  @Before
  public void init() {
    service = new MockService();
    processor = constructProcessor();
  }
  
  @Test(expected = RequestArgumentProcessingException.class)
  public void testNullArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(null, service);
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testNullService() throws RequestArgumentProcessingException {
    processor.processRequestArguments(new HashMap<String, Object>(), null);
  }
  
  protected void initBehaviour() {
    RegistrationResponse behaviour = new RegistrationResponse();
    service.getServiceContext().setBehavior(behaviour);
  }
  
  protected void initPreferences() {
    RegistrationRequest clientPreferences = new RegistrationRequest();
    service.getServiceContext().setClientPreferences(clientPreferences);
  }

  protected abstract T constructProcessor();
  
  protected class MockService extends AbstractService {

    public MockService() {
      this(new ServiceContext(), null);
    }
    
    public MockService(Message request) {
      this(new ServiceContext(), null);
      setRequestMessage(request);
    }
    
    public MockService(ServiceContext serviceContext, State state) {
      super(serviceContext, state, null);
    }

    @Override
    protected void doUpdateServiceContext(Message response, String stateKey)
        throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    }

    @Override
    public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
        Map<String, Object> requestArguments) throws RequestArgumentProcessingException {
      return null;
    }

    @Override
    protected Message doConstructRequest(Map<String, Object> requestArguments)
        throws RequestArgumentProcessingException {
      return null;
    }
  }
}
