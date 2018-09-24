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
import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link AddScope}.
 */
public class AddScopeTest extends BaseRequestArgumentProcessorTest<AddScope> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
  }

  @Override
  protected AddScope constructProcessor() {
    return new AddScope();
  }

  @Test
  public void testAddScopeNoArguments() throws RequestArgumentProcessingException {
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("openid", (String) requestArguments.get("scope"));
  }
  
  @Test
  public void testAddScopeEmptyScope() throws RequestArgumentProcessingException {
    requestArguments.put("scope", "");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertEquals("openid", (String) requestArguments.get("scope"));
  }

  @Test
  public void testModifyScope() throws RequestArgumentProcessingException {
    requestArguments.put("scope", "email profile");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(1, requestArguments.size());
    Assert.assertTrue(
        Pattern.compile("\\bopenid\\b").matcher((String) requestArguments.get("scope")).find());
    Assert.assertTrue(
        Pattern.compile("\\bemail\\b").matcher((String) requestArguments.get("scope")).find());
    Assert.assertTrue(
        Pattern.compile("\\bprofile\\b").matcher((String) requestArguments.get("scope")).find());
  }

}
