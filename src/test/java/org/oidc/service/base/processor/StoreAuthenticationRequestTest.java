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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.MessageType;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link StoreAuthenticationRequest}.
 */
public class StoreAuthenticationRequestTest
    extends BaseRequestArgumentProcessorTest<StoreAuthenticationRequest> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();

  }

  @Override
  protected StoreAuthenticationRequest constructProcessor() {
    return new StoreAuthenticationRequest();
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testStoreAuthenticationRequestNoArguments()
      throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
  }

  @Test
  public void testStoreAuthenticationRequest() throws RequestArgumentProcessingException {
    requestArguments.put("state", "U09NRVJBTkRPTVNUQVRF");
    service = new MockService(new AuthenticationRequest());
    service.getState().createStateRecord("issuer", "U09NRVJBTkRPTVNUQVRF");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertNotNull(
        service.getState().getItem("U09NRVJBTkRPTVNUQVRF", MessageType.AUTHORIZATION_REQUEST));
  }

}
