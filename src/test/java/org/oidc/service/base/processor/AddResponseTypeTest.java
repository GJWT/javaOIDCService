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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link AddResponseType}.
 */
public class AddResponseTypeTest extends BaseRequestArgumentProcessorTest<AddResponseType> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
  }

  @Override
  protected AddResponseType constructProcessor() {
    return new AddResponseType();
  }

  @Test
  public void testPreserveResponseType() throws RequestArgumentProcessingException {
    requestArguments.put("response_type", "code");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("code", (String) requestArguments.get("response_type"));
  }

  @Test
  public void testAddResponseType() throws RequestArgumentProcessingException {
    initBehaviour();
    service.getServiceContext().getBehavior().getClaims().put("response_types",
        Arrays.asList("code", "code id_token"));
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("code", (String) requestArguments.get("response_type"));
  }

}
