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

package org.oidc.service.oidc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oidc.JsonResponseDescriptor;
import org.oidc.msg.oidc.Link;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.WebfingerRequest;
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
    this.expectedResponseClass = JsonResponseDescriptor.class;
  }

  public Webfinger(ServiceContext serviceContext) {
    this(serviceContext, null, null);
  }

  public Webfinger(ServiceContext serviceContext, ServiceConfig serviceConfig) {
    this(serviceContext, null, serviceConfig);
  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (stateKey != null) {
      throw new UnsupportedOperationException(
          "stateKey is not supported to update service context" + " for the WebFinger service");
    }
    @SuppressWarnings("unchecked")
    List<Link> links = (List<Link>) response.getClaims().get(Constants.WEBFINGER_LINKS);

    for (Link link : links) {
      String rel = (String) link.getClaims().get("rel");
      if (!Strings.isNullOrEmpty(rel) && rel.equals(linkRelationType)) {
        String href = (String) link.getClaims().get("href");
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

  /**
   * The idea is to retrieve the host and port from the resource and discard other things like path,
   * query, fragment. The schema can be one of the 3 values: https, acct (when resource looks like
   * email address), device.
   *
   * @param requestArguments
   *          The request arguments must have String-values for resource and rel.
   * @return
   * @throws Exception
   */
  protected String getEndpointWithoutQuery(String resource) throws ValueException,
      MalformedURLException, UnsupportedEncodingException {
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
      throw new MalformedURLException(resource + " has an unknown schema");
    }
    return String.format(Constants.WEB_FINGER_URL, host);
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments)
      throws ValueException, MissingRequiredAttributeException, JsonProcessingException,
      UnsupportedSerializationTypeException, SerializationException, InvalidClaimException {
    String resource = URIUtil
        .normalizeUrl((String) requestArguments.get(Constants.WEBFINGER_RESOURCE));
    requestArguments.put(Constants.WEBFINGER_RESOURCE, resource);
    try {
      String endpoint = getEndpointWithoutQuery(resource);
      httpArguments.setUrl(endpoint + this.requestMessage.toUrlEncoded());
    } catch (UnsupportedEncodingException e) {
      throw new SerializationException(e.getMessage(), e);
    } catch (MalformedURLException  e) {
      throw new InvalidClaimException(e.getMessage(), e);
    }
    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws MissingRequiredAttributeException {
    for (String value : Arrays.asList((String) requestArguments.get(Constants.WEBFINGER_RESOURCE),
        getAddedClaims() == null ? null : getAddedClaims().getResource(),
        this.serviceContext.getBaseUrl())) {
      if (!Strings.isNullOrEmpty(value)) {
        requestArguments.put(Constants.WEBFINGER_RESOURCE, value);
        break;
      }
    }
    if (Strings.isNullOrEmpty((String) requestArguments.get(Constants.WEBFINGER_RESOURCE))) {
      throw new MissingRequiredAttributeException("resource attribute is missing");
    }
    if (Strings.isNullOrEmpty((String) requestArguments.get(Constants.WEBFINGER_REL))) {
      requestArguments.put(Constants.WEBFINGER_REL, linkRelationType);
    }
    WebfingerRequest message = new WebfingerRequest(requestArguments);
    return message;
  }
}