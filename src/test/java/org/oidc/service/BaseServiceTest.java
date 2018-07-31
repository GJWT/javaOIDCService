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

package org.oidc.service;

import java.util.HashMap;

import org.junit.Assert;
import org.junit.Test;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.ResponseMessage;

public abstract class BaseServiceTest<T extends AbstractService> {

  /** The service to be tested. */
  protected T service;

  @Test(expected = ValueException.class)
  public void testUpdateContextNullResponse()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    service.updateServiceContext(null);
  }

  @Test(expected = ValueException.class)
  public void testUpdateContextWrongFormat()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    service.updateServiceContext(new MockMessage());
  }
  
  @Test
  public void testUpdateContextErrorMessage()
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    // Skip check if the expected response class is not extending ResponseMessage
    if (!ResponseMessage.class.isAssignableFrom(service.getExpectedResponseClass())) {
      return;
    }
    boolean catched = false;
    try {
      service.updateServiceContext(buildErrorMessage());
    } catch (ValueException e) {
      catched = true;
    }
    Assert.assertTrue(catched);
    Assert.assertTrue(service.getResponseMessage().getClaims().containsKey("error"));
  }

  protected ResponseMessage buildErrorMessage() throws InvalidClaimException {
    ResponseMessage response = new ResponseMessage();
    response.addClaim("error", "custom_error");
    response.addClaim("error_description", "Custom error description");
    return response;
  }
  
  class MockMessage extends AbstractMessage {

    public MockMessage() {
      super(new HashMap<String, Object>());
    }
  }
}
