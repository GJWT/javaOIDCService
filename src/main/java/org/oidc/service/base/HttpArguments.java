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

package org.oidc.service.base;

import org.oidc.common.HttpMethod;

/**
 * HttpArguments containing Http method, url, body, and header
 */
public class HttpArguments {

  /**
   * Specifies whether it is a POST or GET request. GET by default.
   */
  private HttpMethod httpMethod;
  
  /**
   * The url of the resource.
   */
  private String url;
  
  /**
   * Used to carry the entity-body associated with the request or response (optional).
   */
  private String body;
  
  /**
   * Defines the operating parameters of the Http transaction.
   */
  private HttpHeader header;

  /**
   * @param httpMethod Specifies whether it is a POST or GET request.
   * @param url The url of the resource.
   * @param body Used to carry the entity-body associated with the request or response (optional).
   * @param header Defines the operating parameters of the Http transaction.
   */
  public HttpArguments(HttpMethod httpMethod, String url, String body, HttpHeader header) {
    this.httpMethod = httpMethod;
    this.url = url;
    this.body = body;
    this.header = header == null ? new HttpHeader() : header;
  }

  /**
   * Constructor.
   * 
   * @param httpMethod Specifies whether it is a POST or GET request.
   * @param url The url of the resource.
   */
  public HttpArguments(HttpMethod httpMethod, String url) {
    this(httpMethod, url, null, null);
  }

  /**
   * Constructor.
   * 
   * @param httpMethod Specifies whether it is a POST or GET request.
   */
  public HttpArguments(HttpMethod httpMethod) {
    this(httpMethod, null);
  }

  /**
   * Constructor. Sets method to GET.
   */
  public HttpArguments() {
    this(HttpMethod.GET);
  }

  /**
   * Get the HTTP method.
   * @return The HTTP method.
   */
  public HttpMethod getHttpMethod() {
    return httpMethod;
  }

  /**
   * Set the HTTP method.
   * @param httpMethod What to set.
   */
  public void setHttpMethod(HttpMethod httpMethod) {
    this.httpMethod = httpMethod;
  }

  /**
   * Get the url of the resource.
   * @return The url of the resource.
   */
  public String getUrl() {
    return url;
  }

  /**
   * Set the url of the resource
   * @param url What to set.
   */
  public void setUrl(String url) {
    this.url = url;
  }

  /**
   * Get the entity-body associated with the request or response (optional).
   * @return The entity-body associated with the request or response (optional)
   */
  public String getBody() {
    return body;
  }

  /**
   * Set the entity-body associated with the request or response (optional)
   * @param body What to set.
   */
  public void setBody(String body) {
    this.body = body;
  }

  /**
   * Get the operating parameters of the Http transaction.
   * @return The operating parameters of the Http transaction.
   */
  public HttpHeader getHeader() {
    return header;
  }

  /**
   * Set the operating parameters of the Http transaction.
   * @param header What to set.
   */
  public void setHeader(HttpHeader header) {
    this.header = header;
  }
}