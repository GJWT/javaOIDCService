package org.oidc.services;

import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;
import org.oidc.common.AddedClaims;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.JsonResponseDescriptor;
import org.oidc.msg.Link;
import org.oidc.msg.Message;
import org.oidc.msg.WebfingerRequest;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;
import org.oidc.service.util.URIUtil;

/**
 * Webfinger is used to discover information about people or other entities on the Internet using
 * standard HTTP protocols. WebFinger discovers information for a URI that might not be usable as a
 * locator otherwise, such as account or email URIs. See for more info:
 * https://tools.ietf.org/html/rfc7033
 */
public class Webfinger extends AbstractService {

  /**
   * Constants
   */
  private static final String UTF_8 = "UTF-8";

  public Webfinger(ServiceContext serviceContext, State state, ServiceConfig config) {
    super(serviceContext, state, config);
    this.serviceName = ServiceName.WEB_FINGER;
    this.requestMessage = new WebfingerRequest();
    this.responseMessage = new JsonResponseDescriptor();
  }

  public Webfinger(ServiceContext serviceContext) {
    this(serviceContext, null, null);
  }

  public Webfinger(ServiceContext serviceContext, ServiceConfig serviceConfig) {
    this(serviceContext, null, serviceConfig);
  }

  /**
   * This method will run after the response has been parsed and verified. It requires response in
   * order for the service context to be updated. This method may update certain attributes of the
   * service context such as issuer, clientId, or clientSecret. This method does not require a
   * stateKey since it is used for services that are not expected to store state in the state DB.
   *
   * @param response
   *          the response as a Message instance
   * @throws InvalidClaimException
   */
  @Override
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    List<Link> links = (List<Link>) response.getClaims().get(Constants.WEBFINGER_LINKS);

    String href;
    for (Link link : links) {
      String rel = (String) link.getClaims().get("rel");
      if (!Strings.isNullOrEmpty(rel) && rel.equals(linkRelationType)) {
        href = (String) link.getClaims().get("href");
        // allows for non-standard behavior for schema and issuer
        if (!serviceConfig.isShouldAllowHttp() || !serviceConfig.isShouldAllowNonStandardIssuer()) {
          throw new ValueException("http link not allowed: " + href);
        }
        this.serviceContext.setIssuer(href);
        // pick the first one
        break;
      }
    }
  }

  public void updateServiceContext(Message response, String stateKey) {
    throw new UnsupportedOperationException(
        "stateKey is not supported to update service context" + " for the WebFinger service");
  }

  /**
   * The idea is to retrieve the host and port from the resource and discard other things like path,
   * query, fragment. The schema can be one of the 3 values: https, acct (when resource looks like
   * email address), device.
   *
   * @param resource
   * @return
   * @throws Exception
   */
  public String getQuery(String resource) throws ValueException, MalformedURLException,
      WebFingerException, UnsupportedEncodingException {
    resource = URIUtil.normalizeUrl(resource);
    String host;
    if (resource.startsWith("http")) {
      URL url = new URL(resource);
      host = url.getHost();
      int port = url.getPort();
      if (port != -1) {
        host += ":" + port;
      }
    } else if (resource.startsWith("acct:")) {
      String[] hostArr = resource.split("@");
      if (hostArr != null && hostArr.length > 0) {
        String[] hostArrSplit = hostArr[hostArr.length - 1].replace("/", "#").replace("?", "#")
            .split("#");
        if (hostArrSplit != null && hostArrSplit.length > 0) {
          host = hostArrSplit[0];
        } else {
          throw new ValueException("host cannot be split properly");
        }
      } else {
        throw new ValueException("host cannot be split properly");
      }
    } else if (resource.startsWith("device:")) {
      String[] resourceArrSplit = resource.split(":");
      if (resourceArrSplit != null && resourceArrSplit.length > 1) {
        host = resourceArrSplit[1].replace("/", "#").replace("?", "#").split("#")[0];
      } else {
        throw new ValueException("resource cannot be split properly");
      }
    } else {
      throw new WebFingerException(resource + " has an unknown schema");
    }

    return String.format(Constants.WEB_FINGER_URL, host) + "?resource="
        + URLEncoder.encode(resource, UTF_8) + "&rel=" + URLEncoder.encode(linkRelationType, UTF_8);
  }

  /**
   * Builds the request message and constructs the HTTP headers.
   *
   * This is the starting pont for a pipeline that will:
   *
   * - construct the request message - add/remove information to/from the request message in the way
   * a specific client authentication method requires. - gather a set of HTTP headers like
   * Content-type and Authorization. - serialize the request message into the necessary format
   * (JSON, urlencoded, signed JWT)
   *
   * @param requestArguments
   *          will contain the value for resource
   * @return HttpArguments
   */
  @Override
  public HttpArguments getRequestParameters(Map<String, String> requestArguments)
      throws MissingRequiredAttributeException, MalformedURLException, WebFingerException,
      ValueException, UnsupportedEncodingException {
    if (requestArguments == null) {
      throw new IllegalArgumentException("null requestArguments");
    }

    String resource = requestArguments.get(Constants.WEBFINGER_RESOURCE);
    AddedClaims addedClaims = getAddedClaims();
    if (Strings.isNullOrEmpty(resource)) {
      resource = addedClaims.getResource();
      if (Strings.isNullOrEmpty(resource)) {
        resource = this.serviceContext.getBaseUrl();
      }
      if (Strings.isNullOrEmpty(resource)) {
        throw new MissingRequiredAttributeException("resource attribute is missing");
      }
    }

    HttpArguments httpArguments = new HttpArguments(HttpMethod.GET, this.getQuery(resource));
    return httpArguments;
  }
}