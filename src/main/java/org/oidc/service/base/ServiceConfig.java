package org.oidc.service.base;

import java.util.Map;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.SerializationType;

/**
 * Configuration that is specific to every service
 */
public class ServiceConfig {

  /**
   * A URL defined where this service can be found at the Authorization server
   */
  private String endpoint;
  /**
   * Which client authentication method that should be used for this service if any.
   */
  private ClientAuthenticationMethod defaultAuthenticationMethod;
  /**
   * The HTTP method (POST, GET) that are to be used to transmit the request.
   */
  private HttpMethod httpMethod;
  /**
   * The serialization method to be used on the request before sending
   */
  private SerializationType serializationType;
  /**
   * The deserialization method to be used when deserializing the response
   */
  private SerializationType deSerializationType;
  /**
   * Arguments to be used by the preConstruct methods
   */
  private Map<String, String> preConstruct;
  /**
   * Arguments to be used by the postConstruct methods
   */
  private Map<String, String> postConstruct;
  /**
   * The OIDC standard in many places states that you *MUST* use HTTPS and not HTTP. In a number of
   * use cases, that causes a problem. Therefore, the libraries should still be used in those use
   * cases, hence there has to be a way to turn off the default 'only HTTPS is allowed'.
   */
  private boolean shouldAllowHttp;
  /**
   * Allows for nonstandard behavior for schema and issuer
   */
  private boolean shouldAllowNonStandardIssuer;

  public ServiceConfig(String endpoint, ClientAuthenticationMethod defaultAuthenticationMethod,
      HttpMethod httpMethod, SerializationType serializationType,
      SerializationType deSerializationType, Map<String, String> preConstruct,
      Map<String, String> postConstruct, boolean shouldAllowHttp,
      boolean shouldAllowNonStandardIssuer) {
    this.endpoint = endpoint;
    this.defaultAuthenticationMethod = defaultAuthenticationMethod;
    this.httpMethod = httpMethod;
    this.serializationType = serializationType;
    this.deSerializationType = deSerializationType;
    this.preConstruct = preConstruct;
    this.postConstruct = postConstruct;
    this.shouldAllowHttp = shouldAllowHttp;
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }

  public ServiceConfig(boolean shouldAllowHttp, boolean shouldAllowNonStandardIssuer) {
    this.shouldAllowHttp = shouldAllowHttp;
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
  }

  public ClientAuthenticationMethod getDefaultAuthenticationMethod() {
    return defaultAuthenticationMethod;
  }

  public void setDefaultAuthenticationMethod(
      ClientAuthenticationMethod defaultAuthenticationMethod) {
    this.defaultAuthenticationMethod = defaultAuthenticationMethod;
  }

  public HttpMethod getHttpMethod() {
    return httpMethod;
  }

  public void setHttpMethod(HttpMethod httpMethod) {
    this.httpMethod = httpMethod;
  }

  public SerializationType getSerializationType() {
    return serializationType;
  }

  public void setSerializationType(SerializationType serializationType) {
    this.serializationType = serializationType;
  }

  public SerializationType getDeSerializationType() {
    return deSerializationType;
  }

  public void setDeSerializationType(SerializationType deSerializationType) {
    this.deSerializationType = deSerializationType;
  }

  public Map<String, String> getPreConstruct() {
    return preConstruct;
  }

  public void setPreConstruct(Map<String, String> preConstruct) {
    this.preConstruct = preConstruct;
  }

  public Map<String, String> getPostConstruct() {
    return postConstruct;
  }

  public void setPostConstruct(Map<String, String> postConstruct) {
    this.postConstruct = postConstruct;
  }

  public boolean isShouldAllowHttp() {
    return shouldAllowHttp;
  }

  public void setShouldAllowHttp(boolean shouldAllowHttp) {
    this.shouldAllowHttp = shouldAllowHttp;
  }

  public boolean isShouldAllowNonStandardIssuer() {
    return shouldAllowNonStandardIssuer;
  }

  public void setShouldAllowNonStandardIssuer(boolean shouldAllowNonStandardIssuer) {
    this.shouldAllowNonStandardIssuer = shouldAllowNonStandardIssuer;
  }
}
