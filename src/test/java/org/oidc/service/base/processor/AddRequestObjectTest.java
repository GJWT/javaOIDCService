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

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.msg.Key;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
  String issuer = "https://op.example.com";

  @Before
  public void initTest() throws CertificateException, IOException, JWKException,
      IllegalArgumentException, ImportException, UnknownKeyType, ValueError {
    requestArguments = new HashMap<String, Object>();
    requestArguments.put("claim1", "value1");
    requestArguments.put("claim2", "value2");
    service.getPostConstructorArgs().put("request_method", "request");
    service.getPostConstructorArgs().put("request_object_signing_alg", "RS512");
    service.getPostConstructorArgs().put("key", (Key) KeyUtil.getRSAPrvKey());
    service.getServiceContext().setIssuer(issuer);
    service.getServiceContext().setBaseUrl("http://example.com");
    service.getServiceContext().setKeyJar(KeyUtil.getKeyJarPrv(""));
    service.getServiceContext().getKeyJar().addKeyBundle(issuer,
        KeyUtil.getKeyJarPrv(issuer).getBundle(issuer).get(0));
    service.getServiceContext().setBehavior(new RegistrationResponse());
    service.getServiceContext().setRequestsDirectory(System.getProperty("java.io.tmpdir"));
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
    Assert.assertTrue(
        !requestArguments.containsKey("request") && !requestArguments.containsKey("request_uri"));
  }

  private void AddRequestObject()
      throws RequestArgumentProcessingException, IllegalArgumentException, DeserializationException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals(3, requestArguments.size());
    Assert.assertTrue(requestArguments.containsKey("request"));
    RequestObject reqObject = new RequestObject();
    reqObject.fromJwt((String) requestArguments.get("request"), KeyUtil.getKeyJarPub(issuer),
        issuer);
    Assert.assertEquals("value1", reqObject.getClaims().get("claim1"));
    Assert.assertEquals("value2", reqObject.getClaims().get("claim2"));
  }

  @Test
  public void AddRequestObjectByReference()
      throws RequestArgumentProcessingException, IllegalArgumentException, DeserializationException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    List<String> requestURIs = new ArrayList<String>();
    requestURIs.add("http://example.com/requesturifile");
    service.getPostConstructorArgs().put("request_method", "request_uri");
    service.getServiceContext().getBehavior().getClaims().put("request_uris", requestURIs);
    processor.processRequestArguments(requestArguments, service);
    Assert.assertEquals("http://example.com/requesturifile", requestArguments.get("request_uri"));
  }

  @Test
  public void AddRequestObjectByReferenceNoFile()
      throws RequestArgumentProcessingException, IllegalArgumentException, DeserializationException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    service.getPostConstructorArgs().put("request_method", "request_uri");
    processor.processRequestArguments(requestArguments, service);
    Assert.assertTrue(((String) requestArguments.get("request_uri"))
        .contains(System.getProperty("java.io.tmpdir")));
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
  public void testAddRequestObjectEncrypted()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException, CertificateException {
    service.getPostConstructorArgs().put("request_object_encryption_alg", "RSA1_5");
    service.getPostConstructorArgs().put("request_object_encryption_enc", "A128CBC-HS256");
    service.getPostConstructorArgs().put("keytransport_key", (Key) KeyUtil.getRSAPrvKey());
    processor.processRequestArguments(requestArguments, service);
    DecodedJWT decodedJwt = JWT.decode((String) requestArguments.get("request"));
    Assert.assertTrue(decodedJwt.isJWE());
  }

  @Test
  public void testAddRequestObjectEncryptedKeyInKeyJar()
      throws RequestArgumentProcessingException, DeserializationException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, JWKException, CertificateException {
    service.getPostConstructorArgs().put("request_object_encryption_alg", "RSA1_5");
    service.getPostConstructorArgs().put("request_object_encryption_enc", "A128CBC-HS256");
    processor.processRequestArguments(requestArguments, service);
    DecodedJWT decodedJwt = JWT.decode((String) requestArguments.get("request"));
    Assert.assertTrue(decodedJwt.isJWE());
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
