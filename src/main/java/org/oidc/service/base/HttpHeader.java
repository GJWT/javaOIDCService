package org.oidc.service.base;

/**
 * Contains authorization and content-type that defines the operating parameters of the Http
 * transaction
 */
public class HttpHeader {

  /**
   * Contains the credentials needed to authenticate a user agent with a server
   */
  private String authorization;
  /**
   * Indicates the media type (e.g. application/json, application/xml, etc.) of the resource
   */
  private String contentType;

  public HttpHeader(String authorization, String contentType) {
    this.authorization = authorization;
    this.contentType = contentType;
  }

  public String getAuthorization() {
    return authorization;
  }

  public void setAuthorization(String authorization) {
    this.authorization = authorization;
  }

  public String getContentType() {
    return contentType;
  }

  public void setContentType(String contentType) {
    this.contentType = contentType;
  }
}