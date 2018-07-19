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

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.oidc.common.ValueException;

public class URIUtilTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testNormalizeUrlNullUrl() throws ValueException {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("null or empty url");
    URIUtil.normalizeUrl(null);
  }

  @Test
  public void testNormalizeUrlEmptyUrl() throws ValueException {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("null or empty url");
    URIUtil.normalizeUrl("");
  }

  @Test
  public void testNormalizeUrl() throws ValueException {
    String normalizedUrl = URIUtil.normalizeUrl("foobar@example.org");
    Assert.assertTrue(normalizedUrl.equals("acct:foobar@example.org"));
  }

  @Test
  public void testNormalizeUrlThatsAlreadyBeenNormalizedForDevice() throws ValueException {
    String normalizedUrl = URIUtil.normalizeUrl("device:p1.example.com");
    Assert.assertTrue(normalizedUrl.equals("device:p1.example.com"));
  }

  @Test
  public void testNormalizeUrlThatsAlreadyBeenNormalizedForAcct() throws ValueException {
    String normalizedUrl = URIUtil.normalizeUrl("acct:bob@example.com");
    Assert.assertTrue(normalizedUrl.equals("acct:bob@example.com"));
  }
}
