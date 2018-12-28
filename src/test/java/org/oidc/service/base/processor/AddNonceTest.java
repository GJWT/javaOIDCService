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
 * Unit tests for {@link AddNonce}.
 */
public class AddNonceTest extends BaseRequestArgumentProcessorTest<AddNonce> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
  }

  @Override
  protected AddNonce constructProcessor() {
    return new AddNonce();
  }

  @Test
  public void testAddNonceNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
  }

  @Test
  public void testAddNonceIdToken() throws RequestArgumentProcessingException {
    requestArguments.put("response_type", "code id_token token");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(2, requestArguments.size());
    Assert.assertTrue(requestArguments.containsKey("nonce"));
  }

  @Test
  public void testPreserveNonce() throws RequestArgumentProcessingException {
    requestArguments.put("nonce", "U09NRVJBTkRPTU5PTkNF");
    requestArguments.put("response_type", "code id_token token");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("U09NRVJBTkRPTU5PTkNF", (String) requestArguments.get("nonce"));
  }

}
