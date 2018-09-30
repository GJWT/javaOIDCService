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

public class Constants {

  /**
   * Service configuration property keys.
   */
  public static final String SERVICE_CONFIG_KEY_SERVICE_NAME = "name";
  public static final String SERVICE_CONFIG_KEY_ENDPOINT = "endpoint";
  public static final String SERVICE_CONFIG_KEY_DEFAULT_AUTHENTICATION_METHOD = "default_authentication_method";
  public static final String SERVICE_CONFIG_KEY_HTTP_METHOD = "http_method";
  public static final String SERVICE_CONFIG_KEY_SERIALIZATION_TYPE = "serialization_type";
  public static final String SERVICE_CONFIG_KEY_DESERIALIZATION_TYPE = "deserialization_type";
  public static final String SERVICE_CONFIG_KEY_PRE_CONSTRUCTORS = "pre_constructors";
  public static final String SERVICE_CONFIG_KEY_POST_CONSTRUCTORS = "post_constructors";
  public static final String SERVICE_CONFIG_KEY_SHOULD_ALLOW_HTTP = "allow_http";
  public static final String SERVICE_CONFIG_KEY_ALLOW_NON_STANDARD_ISSUER = "allow_non_standard_issuer";

  public static final String OIDC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";
  public static final String WEB_FINGER_URL = "https://%s/.well-known/webfinger";
  public static final String OIDCONF_PATTERN = "%s/.well-known/openid-configuration";

  public static final String ALLOW_PARAM_ISSUER_MISMATCH = "issuer_mismatch";

  /**
   * Claims
   */
  public static final String CLIENT_ID = "clientId";
  public static final String ISSUER = "issuer";
  public static final String KEY_JAR = "keyJar";
  public static final String SHOULD_VERIFY = "shouldVerify";
  public static final String SUBJECT = "subject";
  public static final String LINKS = "links";
  public static final String EXPIRES = "expires";
  public static final String GRANT_TYPE = "grantType";

  public static final String WEBFINGER_SUBJECT = "subject";
  public static final String WEBFINGER_ALIASES = "aliases";
  public static final String WEBFINGER_PROPERTIES = "properties";
  public static final String WEBFINGER_LINKS = "links";
  public static final String WEBFINGER_REL = "rel";
  public static final String WEBFINGER_TYPE = "type";
  public static final String WEBFINGER_HREF = "href";
  public static final String WEBFINGER_TITLES = "titles";
  public static final String WEBFINGER_RESOURCE = "resource";
}
