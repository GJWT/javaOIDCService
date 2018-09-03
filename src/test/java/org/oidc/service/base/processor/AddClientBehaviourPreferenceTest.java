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
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;
import org.oidc.service.base.RequestArgumentProcessingException;

/**
 * Unit tests for {@link AddClientBehaviourPreference}.
 */
public class AddClientBehaviourPreferenceTest
    extends BaseRequestArgumentProcessorTest<AddClientBehaviourPreference> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
  }

  @Override
  protected AddClientBehaviourPreference constructProcessor() {
    return new AddClientBehaviourPreference();
  }

  @Test
  public void testNoBehaviourNorPreferencesNoArguments() throws RequestArgumentProcessingException {
    AddClientBehaviourPreference processor = new AddClientBehaviourPreference();
    service = new MockService(new MockMessage());
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(0, requestArguments.size());
  }

  @Test
  public void testNoBehaviourNorPreferencesWithArguments()
      throws RequestArgumentProcessingException {
    AddClientBehaviourPreference processor = new AddClientBehaviourPreference();
    service = new MockService(new MockMessage());
    requestArguments.put("mockString", "value");
    requestArguments.put("mockList", Arrays.asList("v1", "v2", "v3"));
    requestArguments.put("mockArray", "value1 value2");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertEquals("value", requestArguments.get("mockString"));
    Assert.assertEquals(Arrays.asList("v1", "v2", "v3"), requestArguments.get("mockList"));
    Assert.assertEquals("value1 value2", requestArguments.get("mockArray"));
  }

  @Test
  public void testBehaviourNoPreferences() throws RequestArgumentProcessingException {
    AddClientBehaviourPreference processor = new AddClientBehaviourPreference();
    service = new MockService(new MockMessage());
    initBehaviour();
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertEquals("behaviourValue", requestArguments.get("mockString"));
    Assert.assertEquals(Arrays.asList("bv1", "bv2", "bv3"), requestArguments.get("mockList"));
    Assert.assertEquals("bvalue1 bvalue2", requestArguments.get("mockArray"));
  }

  @Test
  public void testPreferencesNoBehaviour() throws RequestArgumentProcessingException {
    AddClientBehaviourPreference processor = new AddClientBehaviourPreference();
    service = new MockService(new MockMessage());
    initPreferences();
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertEquals("preferenceValue", requestArguments.get("mockString"));
    Assert.assertEquals(Arrays.asList("pv1", "pv2", "pv3"), requestArguments.get("mockList"));
    Assert.assertEquals("prefvalue1 prefvalue2", requestArguments.get("mockArray"));
  }

  @Test
  public void testBehaviourAndPreferences() throws RequestArgumentProcessingException {
    AddClientBehaviourPreference processor = new AddClientBehaviourPreference();
    service = new MockService(new MockMessage());
    initBehaviour();
    initPreferences();
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertEquals("behaviourValue", requestArguments.get("mockString"));
    Assert.assertEquals(Arrays.asList("bv1", "bv2", "bv3"), requestArguments.get("mockList"));
    Assert.assertEquals("bvalue1 bvalue2", requestArguments.get("mockArray"));
  }

  protected void initPreferences() {
    super.initPreferences();
    service.getServiceContext().getClientPreferences().getClaims().put("mockString",
        "preferenceValue");
    service.getServiceContext().getClientPreferences().getClaims().put("mockList",
        Arrays.asList("pv1", "pv2", "pv3"));
    service.getServiceContext().getClientPreferences().getClaims().put("mockArray",
        "prefvalue1 prefvalue2");
  }

  protected void initBehaviour() {
    super.initBehaviour();
    service.getServiceContext().getBehavior().getClaims().put("mockString", "behaviourValue");
    service.getServiceContext().getBehavior().getClaims().put("mockList",
        Arrays.asList("bv1", "bv2", "bv3"));
    service.getServiceContext().getBehavior().getClaims().put("mockArray", "bvalue1 bvalue2");
  }

  protected class MockMessage extends AbstractMessage {

    {
      paramVerDefs.put("mockString", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("mockList", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
      paramVerDefs.put("mockArray",
          ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    }

    public MockMessage() {
      super(new HashMap<String, Object>());
    }

  }
}
