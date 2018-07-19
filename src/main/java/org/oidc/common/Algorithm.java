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

package org.oidc.common;

/**
 * All the algorithms that can be used for signing or verifying a token as determined by Auth0
 */
public enum Algorithm {
  /**
   * RS256 algorithm
   **/
  RS256,
  /**
   * RS384 algorithm
   **/
  RS384,
  /**
   * RS512 algorithm
   **/
  RS512,
  /**
   * HS256 algorithm
   **/
  HS256,
  /**
   * HS384 algorithm
   **/
  HS384,
  /**
   * HS512 algorithm
   **/
  HS512,
  /**
   * ES256 algorithm
   **/
  ES256,
  /**
   * ES384 algorithm
   **/
  ES384,
  /**
   * ES512 algorithm
   **/
  ES512;
}