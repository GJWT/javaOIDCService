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
 * Unit tests for {@link StoreNonce}.
 */
public class StoreNonceTest extends BaseRequestArgumentProcessorTest<StoreNonce> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
    service.getState().createStateRecord("issuer", "U09NRVJBTkRPTVNUQVRF");
  }

  @Override
  protected StoreNonce constructProcessor() {
    return new StoreNonce();
  }

  @Test
  public void testStoreNonceNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
  }

  @Test
  public void testStoreNonce() throws RequestArgumentProcessingException {
    requestArguments.put("state", "U09NRVJBTkRPTVNUQVRF");
    requestArguments.put("nonce", "U09NRVJBTkRPTU5PTkNF");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("U09NRVJBTkRPTVNUQVRF",
        service.getState().getStateKeyByNonce("U09NRVJBTkRPTU5PTkNF"));
  }

}
