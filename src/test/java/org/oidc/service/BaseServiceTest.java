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

import org.junit.Test;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;

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

  class MockMessage extends AbstractMessage {

    public MockMessage() {
      super(new HashMap<String, Object>());
    }
  }
}
