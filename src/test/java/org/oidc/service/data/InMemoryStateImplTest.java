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

package org.oidc.service.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.common.MessageType;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;

/**
 * Unit tests for {@link InMemoryStateImpl}.
 */
public class InMemoryStateImplTest {

  private InMemoryStateImpl stateDb = new InMemoryStateImpl();
  private String state;

  @Before
  public void init() {
    state = stateDb.createStateRecord("issuer", null);
  }

  @Test
  public void testStateLength() throws Exception {
    Assert.assertEquals(44, state.length());
  }

  @Test
  public void testIssuer() throws Exception {
    Assert.assertEquals("issuer", stateDb.getState(state).getClaims().get("iss"));
  }

  @Test
  public void testStoreAndGetItem() throws Exception {
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.getClaims().put("redirect_uri", "https://example.com");
    Assert.assertTrue(
        stateDb.storeItem(authenticationRequest, state, MessageType.AUTHORIZATION_REQUEST));
    Assert.assertEquals("https://example.com",
        stateDb.getItem(state, MessageType.AUTHORIZATION_REQUEST).getClaims().get("redirect_uri"));
  }

  @Test
  public void testStoreFailure() throws Exception {
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.getClaims().put("redirect_uri", "https://example.com");
    Assert.assertFalse(
        stateDb.storeItem(authenticationRequest, state, MessageType.AUTHORIZATION_RESPONSE));
    Assert.assertNull(stateDb.getItem(state, MessageType.AUTHORIZATION_RESPONSE));
  }

  @Test
  public void testExtendArgs() throws Exception {
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.getClaims().put("redirect_uri", "https://example.com");
    AuthenticationResponse authenticationResponse = new AuthenticationResponse();
    authenticationRequest.getClaims().put("expires_in", 5L);
    stateDb.storeItem(authenticationRequest, state, MessageType.AUTHORIZATION_REQUEST);
    stateDb.storeItem(authenticationResponse, state, MessageType.AUTHORIZATION_RESPONSE);
    List<MessageType> messageTypes = new ArrayList<MessageType>();
    messageTypes.add(MessageType.AUTHORIZATION_REQUEST);
    messageTypes.add(MessageType.AUTHORIZATION_RESPONSE);
    List<String> parameters = new ArrayList<String>();
    parameters.add("redirect_uri");
    parameters.add("expires_in");
    Map<String, Object> args = new HashMap<String, Object>();
    stateDb.multipleExtendRequestArgs(args, state, parameters, messageTypes);
    Assert.assertEquals(2, args.size());
    Assert.assertEquals("https://example.com", args.get("redirect_uri"));
    Assert.assertEquals(5L, args.get("expires_in"));
  }

  @Test
  public void testSettingNonce() throws Exception {
    stateDb.storeStateKeyForNonce("nonce", state);
    Assert.assertEquals(state, stateDb.getStateKeyByNonce("nonce"));
  }

}
