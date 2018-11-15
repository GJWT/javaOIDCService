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

package org.oidc.service.oidc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.HttpMethod;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.JsonResponseDescriptor;
import org.oidc.msg.oidc.Link;
import org.oidc.service.BaseServiceTest;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;

public class WebfingerTest extends BaseServiceTest<Webfinger> {

  private static final ServiceContext SERVICE_CONTEXT = new ServiceContext();
  private static final String OP_BASEURL = "https://example.org/op";

  @Before
  public void init() {
    service = new Webfinger(SERVICE_CONTEXT);
  }

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test(expected = UnsupportedOperationException.class)
  public void testUpdateServiceContextWrongMethod() throws Exception {
    service.updateServiceContext(buildMinimalJrd(), "mockKey");
  }

  //TODO: Update test. Message is now verified in parse response.
  //@Test(expected = InvalidClaimException.class)
  public void testUpdateServiceContextInvalidMsgContents() throws Exception {
    JsonResponseDescriptor jrd = buildMinimalJrd();
    jrd.addClaim("properties", "this is not a map as it should");
    service.updateServiceContext(jrd);
  }
  

  protected JsonResponseDescriptor buildMinimalJrd() {
    JsonResponseDescriptor jrd = new JsonResponseDescriptor();
    Link link = new Link();
    link.addClaim("rel", "mockRel");
    jrd.addClaim("links", Arrays.asList(link));
    return jrd;
  }

  protected Map<String, Object> buildArgsWithResource(String resource) {
    Map<String, Object> map = new HashMap<>();
    map.put(Constants.WEBFINGER_RESOURCE, resource);
    return map;
  }

  @Test
  public void testGetRequestParametersWithDevice() throws Exception {
    HttpArguments httpArguments = service
        .getRequestParameters(buildArgsWithResource("device:p1.example.com"));
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://p1.example.com/.well-known/webfinger?resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
  }

  @Test
  public void testGetRequestParametersWithAcct() throws Exception {
    HttpArguments httpArguments = service
        .getRequestParameters(buildArgsWithResource("acct:bob@example.com"));
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://example.com/.well-known/webfinger?resource=acct%3Abob%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
  }

  @Test
  public void testGetRequestParametersWithWWWSchema() throws Exception {
    HttpArguments httpArguments = service
        .getRequestParameters(buildArgsWithResource("www.yahoo.com"));
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://www.yahoo.com/.well-known/webfinger?resource=https%3A%2F%2Fwww.yahoo.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testGetQueryWithEmptyResource() throws Exception {
    service.getRequestParameters(buildArgsWithResource(""));
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testGetRequestParametersNullResource() throws Exception {
    service.getRequestParameters(buildArgsWithResource(null));
  }

  @Test(expected = RequestArgumentProcessingException.class)
  public void testGetRequestParametersNullResourceAndNullAddedClaimsResourceAndNullBaseUrl()
      throws Exception {
    service.getRequestParameters(null);
  }

  @Test
  public void testGetRequestParametersUrl() throws Exception {
    Map<String, Object> requestArguments = new HashMap<String, Object>();
    requestArguments.put("resource", "acct:bob@example.com");

    HttpArguments httpArguments = service.getRequestParameters(requestArguments);
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://example.com/.well-known/webfinger?resource=acct%3Abob%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
  }

  @Test
  public void testGetRequestParametersAcct() throws Exception {
    Map<String, Object> requestArguments = new HashMap<String, Object>();
    requestArguments.put("resource", "acct:carol@example.com");

    HttpArguments httpArguments = service.getRequestParameters(requestArguments);
    System.out.println(httpArguments.getUrl());
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://example.com/.well-known/webfinger?resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
  }

  @Test
  public void testGetRequestParameters() throws UnsupportedSerializationTypeException, RequestArgumentProcessingException, SerializationException {
    Map<String, String> requestParametersMap = new HashMap<String, String>() {
      {
        put("example.com", "example.com");
        put("example.com:8080", "example.com:8080");
        put("example.com/path", "example.com");
        put("example.com?query", "example.com");
        put("example.com#fragment", "example.com");
        put("example.com:8080/path?query#fragment", "example.com:8080");
        put("http://example.com", "example.com");
        put("http://example.com:8080", "example.com:8080");
        put("http://example.com/path", "example.com");
        put("http://example.com?query", "example.com");
        put("http://example.com#fragment", "example.com");
        put("http://example.com:8080/path?query#fragment", "example.com:8080");
        put("nov@example.com", "example.com");
        put("nov@example.com:8080", "example.com:8080");
        put("nov@example.com/path", "example.com");
        put("nov@example.com?query", "example.com");
        put("nov@example.com#fragment", "example.com");
        put("nov@example.com:8080/path?query#fragment", "example.com:8080");
        put("acct:nov@matake.jp", "matake.jp");
        put("acct:nov@example.com:8080", "example.com:8080");
        put("acct:nov@example.com/path", "example.com");
        put("acct:nov@example.com?query", "example.com");
        put("acct:nov@example.com#fragment", "example.com");
        put("acct:nov@example.com:8080/path?query#fragment", "example.com:8080");
        put("device:192.168.2.1", "192.168.2.1");
        put("device:192.168.2.1:8080", "192.168.2.1");
        put("device:192.168.2.1/path", "192.168.2.1");
        put("device:192.168.2.1?query", "192.168.2.1");
        put("device:192.168.2.1#fragment", "192.168.2.1");
        put("device:192.168.2.1/path?query#fragment", "192.168.2.1");
      }
    };

    Map<String, Object> input = new HashMap<>();
    String[] requestParamsSplit;
    for (String key : requestParametersMap.keySet()) {
      input.put("resource", key);
      HttpArguments requestParams = service.getRequestParameters(input);
      requestParamsSplit = requestParams.getUrl().split("\\?");
      if (!requestParamsSplit[0]
          .equals(String.format(Constants.WEB_FINGER_URL, requestParametersMap.get(key)))) {
        throw new AssertionError("result does not match expected webFinger url");
      }
    }
  }

  @Test
  public void testWebfingerEndToEnd() throws Exception {
    ServiceConfig serviceConfig = new ServiceConfig(true, true);
    Webfinger webfinger = new Webfinger(SERVICE_CONTEXT, serviceConfig);
    Map<String, Object> requestArguments = new HashMap<>();
    requestArguments.put("resource", "foobar@example.org");
    HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
    Assert.assertTrue(httpArguments.getUrl().equals(
        "https://example.org/.well-known/webfinger?resource=acct%3Afoobar%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
    HashMap<String, Object> claims = new HashMap<>();
    Link linkInfo = new Link();
    linkInfo.addClaim("rel", "rel");
    linkInfo.addClaim("href", "href");
    linkInfo.addClaim("type", "type");
    Link secondLinkInfo = new Link();
    secondLinkInfo.addClaim("rel", "http://openid.net/specs/connect/1.0/issuer");
    secondLinkInfo.addClaim("href", OP_BASEURL);
    secondLinkInfo.addClaim("type", "type2");
    claims.put("links", Arrays.asList(linkInfo, secondLinkInfo));
    JsonResponseDescriptor jrd = new JsonResponseDescriptor(claims);
    Message parsedResponse = webfinger.parseResponse(jrd.toJson());
    Assert.assertTrue(parsedResponse instanceof JsonResponseDescriptor);
    Assert.assertTrue(parsedResponse.verify());
    Map<String, Object> expectedClaims = new HashMap<>();
    expectedClaims.put("rel", "rel");
    expectedClaims.put("href", "href");
    expectedClaims.put("type", "type");
    Map<String, Object> secondExpectedClaims = new HashMap<>();
    secondExpectedClaims.put("rel", "http://openid.net/specs/connect/1.0/issuer");
    secondExpectedClaims.put("href", OP_BASEURL);
    secondExpectedClaims.put("type", "type2");
    List<Link> links = (List<Link>) parsedResponse.getClaims().get("links");
    Assert.assertTrue(expectedClaims.values().containsAll(links.get(0).getClaims().values()));
    Assert.assertTrue(secondExpectedClaims.values().containsAll(links.get(1).getClaims().values()));

    webfinger.updateServiceContext(parsedResponse);
    Assert.assertTrue(webfinger.getServiceContext().getIssuer().equals(OP_BASEURL));
  }

}
