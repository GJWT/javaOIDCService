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
 * Types of ClientAuthenticationMethods.
 */
public enum ClientAuthenticationMethod {

  CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, BEARER_HEADER, BEARER_BODY, 
  CLIENT_SECRET_JWT, PRIVATE_KEY_JWT, NONE;

  /**
   * Convert oidc claim value to authentication method enumeration.
   * 
   * @param value
   *          claim value to convert.
   * @return authentication method enumeration, null if there is no match
   */
  public static ClientAuthenticationMethod fromClaimValue(String value) {
    switch (value) {
      case "client_secret_basic":
        return CLIENT_SECRET_BASIC;
      case "client_secret_post":
        return CLIENT_SECRET_POST;
      case "bearer_header":
        return BEARER_HEADER;
      case "bearer_body":
        return BEARER_BODY;
      case "client_secret_jwt":
        return CLIENT_SECRET_JWT;
      case "private_key_jwt":
        return PRIVATE_KEY_JWT;
      case "none":
        return NONE;
      default:
        break;
    }
    return null;
  }

}
