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

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.msg.oidc.RequestObject;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.testutil.KeyUtil;

/**
 * Unit tests for {@link AddRequestObject}.
 */
public class AddRequestObjectTest extends BaseRequestArgumentProcessorTest<AddRequestObject> {

  Map<String, Object> requestArguments;

  @Before
  public void initTest() throws CertificateException, IOException, JWKException,
      IllegalArgumentException, ImportException, UnknownKeyType, ValueError {
    requestArguments = new HashMap<String, Object>();
    service.getPostConstructorArgs().put("request_method", "request");
    service.getPostConstructorArgs().put("request_object_signing_alg", "RS512");
    service.getPostConstructorArgs().put("key", (Key) KeyUtil.getRSAPrvKey());
    service.getServiceContext().setKeyJar(KeyUtil.getKeyJarPrv(""));
    service.getServiceContext().setBehavior(new RegistrationResponse());
    service.getServiceContext().getBehavior().getClaims().put("request_object_signing_alg",
        "RS384");
  }

  @Override
  protected AddRequestObject constructProcessor() {
    return new AddRequestObject();
  }

  @Test
  public void testNotRequested() throws RequestArgumentProcessingException {
    service.getPostConstructorArgs().remove("request_method");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(0, requestArguments.size());
  }

  private void AddRequestObject()
      throws RequestArgumentProcessingException, IllegalArgumentException, DeserializationException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    requestArguments.put("claim1", "value1");
    requestArguments.put("claim2", "value2");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertTrue(requestArguments.containsKey("request"));
    RequestObject reqObject = new RequestObject();
    reqObject.fromJwt((String) requestArguments.get("request"), KeyUtil.getKeyJarPub("issuer"),
        "issuer");
    Assert.assertEquals("value1", reqObject.getClaims().get("claim1"));
    Assert.assertEquals("value2", reqObject.getClaims().get("claim2"));
  }

  @Test
  public void testAddRequestObject()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    AddRequestObject();
  }

  @Test
  public void testAddRequestObjectKeyInBundle()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    service.getPostConstructorArgs().remove("key");
    AddRequestObject();
  }

  @Test
  public void testAddRequestObjectBehaviourAlg()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    service.getPostConstructorArgs().remove("request_object_signing_alg");
    AddRequestObject();
  }

  @Test
  public void testAddRequestObjectDefaultAlg()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    service.getPostConstructorArgs().remove("request_object_signing_alg");
    service.getServiceContext().getBehavior().getClaims().remove("request_object_signing_alg");
    AddRequestObject();
  }

}
