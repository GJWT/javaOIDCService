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
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link AddState}.
 */
public class AddStateTest extends BaseRequestArgumentProcessorTest<AddState> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
    service.getServiceContext().setIssuer("issuer");
  }

  @Override
  protected AddState constructProcessor() {
    return new AddState();
  }

  @Test
  public void testAddStateNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertTrue(requestArguments.containsKey("state"));
    Assert.assertEquals("issuer",
        service.getState().getIssuer((String) requestArguments.get("state")));
  }

  @Test
  public void testPreserveState() throws RequestArgumentProcessingException {
    requestArguments.put("state", "U09NRVJBTkRPTVNUQVRF");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("U09NRVJBTkRPTVNUQVRF", requestArguments.get("state"));
    Assert.assertEquals("issuer",
        service.getState().getIssuer((String) requestArguments.get("state")));
  }

}
