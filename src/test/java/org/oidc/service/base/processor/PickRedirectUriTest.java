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
 * Unit tests for {@link PickRedirectUri}.
 */
public class PickRedirectUriTest extends BaseRequestArgumentProcessorTest<PickRedirectUri> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() {
    requestArguments = new HashMap<String, Object>();
    Map<String, String> callBack = new HashMap<String, String>();
    callBack.put("form_post", "http://example.com/form_post");
    callBack.put("code", "http://example.com/code");
    callBack.put("implicit", "http://example.com/implicit");
    service.getServiceContext().setCallBack(callBack);
    service.getServiceContext()
        .setRedirectUris(Arrays.asList("http://example.com/0", "http://example.com/1"));
  }

  @Override
  protected PickRedirectUri constructProcessor() {
    return new PickRedirectUri();
  }

  @Test
  public void testPreserveRedirectUri() throws RequestArgumentProcessingException {
    requestArguments.put("redirect_uri", "http://example.com");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com", (String) requestArguments.get("redirect_uri"));
  }

  @Test
  public void testPickRedirectUriForFormPost() throws RequestArgumentProcessingException {
    requestArguments.put("response_mode", "form_post");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com/form_post",
        (String) requestArguments.get("redirect_uri"));
  }

  @Test
  public void testPickRedirectUriByResponseType() throws RequestArgumentProcessingException {
    requestArguments.put("response_type", "code id_token token");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com/code", (String) requestArguments.get("redirect_uri"));
    requestArguments.remove("redirect_uri");
    requestArguments.put("response_type", "id_token");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com/implicit",
        (String) requestArguments.get("redirect_uri"));
  }

  @Test
  public void testPickRedirectByServiceContext() throws RequestArgumentProcessingException {
    service.getServiceContext().setCallBack(null);
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com/0", (String) requestArguments.get("redirect_uri"));
  }

}
