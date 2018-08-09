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

package org.oidc.service.util;

import static org.hamcrest.core.StringContains.containsString;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;

public class ServiceUtilTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testGetQueryReferenceNullUrl() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("null or empty url");
    ServiceUtil.getUrlInfo(null);
  }

  @Test
  public void testGetQueryReferenceEmptyUrl() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("null or empty url");
    ServiceUtil.getUrlInfo("");
  }

  @Test
  public void testGetUrlQueryReferenceWithQueryIncluded() throws Exception {
    String url = ServiceUtil.getUrlInfo("https://www.google.co.in/search?q=gnu&rlz=1C1CHZL_enIN71"
        + "4IN715&oq=gnu&aqs=chrome..69i57j69i60l5.653j0j7&sourceid=chrome&ie=UTF"
        + "-8#q=geeks+for+geeks+java");
    Assert.assertTrue(url.equals("q=gnu&rlz=1C1CHZL_enIN714IN715&oq=gnu&aqs=chrome..69i5"
        + "7j69i60l5.653j0j7&sourceid=chrome&ie=UTF-8"));
  }

  @Test
  public void testGetUrlQueryReferenceWithQueryExcluded() throws Exception {
    String url = ServiceUtil.getUrlInfo("https://www.google.co.in/#q=geeks+for+geeks+java");
    Assert.assertTrue(url.equals("q=geeks+for+geeks+java"));
  }

  @Test
  public void testGetHttpBodyWithSerializationTypeUrlEncoded()
      throws UnsupportedSerializationTypeException, JsonProcessingException, SerializationException,
      InvalidClaimException {
    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.ISSUER, "issuer");
    Message request = new MockMessage(claims);
    String httpBody = ServiceUtil.getHttpBody(request, SerializationType.URL_ENCODED);
    System.out.println(httpBody);
    Assert.assertEquals("?issuer=issuer", httpBody);
  }

  @Test
  public void testGetHttpBodyWithSerializationTypeJson()
      throws UnsupportedSerializationTypeException, JsonProcessingException, SerializationException,
      InvalidClaimException {
    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.ISSUER, "issuer");
    Message request = new MockMessage(claims);
    String httpBody = ServiceUtil.getHttpBody(request, SerializationType.JSON);
    Assert.assertTrue(httpBody.equals("{\"issuer\":\"issuer\"}"));
  }

  @Test
  public void testGetHttpBodyWithIncorrectSerializationType()
      throws UnsupportedSerializationTypeException, JsonProcessingException, SerializationException,
      InvalidClaimException {
    thrown.expect(UnsupportedSerializationTypeException.class);
    thrown.expectMessage(containsString("Unsupported serialization type: "));
    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.ISSUER, "issuer");
    Message request = new MockMessage(claims);
    ServiceUtil.getHttpBody(request, SerializationType.JWT);
  }

  class MockMessage extends AbstractMessage {

    public MockMessage(Map<String, Object> claims) {
      super(claims);
    }
  }
}
