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

package org.oidc.service.base.processor;

import com.auth0.msg.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.RequestObject;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.util.ServiceUtil;

/**
 * Class to add request object to the request if post constructor arguments have a string value of
 * 'request' or 'request_uri' for key 'request_method'. Argument list:
 * 
 * <p>
 * 'request_method' - processor is executed if set to 'request' or 'request_uri'.
 * </p>
 * 
 * <p>
 * 'request_object_signing_alg' - algorithm name as listed in
 * https://tools.ietf.org/html/rfc7518#section-3.1. If not set defaults to RS256.
 * </p>
 * 
 * <p>
 * 'key' - Instance of type Key used for signing the request object. If not set key is searched from
 * key jar.
 * </p>
 * 
 * <p>
 * 'sig_kid' - Additional argument for searching the key from key jar.
 * </p>
 */
public class AddRequestObject extends AbstractRequestArgumentProcessor {

  {
    postParamVerDefs.put("request_method", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    postParamVerDefs.put("request_object_signing_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    postParamVerDefs.put("key", ParameterVerification.SINGLE_OPTIONAL_KEY.getValue());
    postParamVerDefs.put("sig_kid", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    String requestMethod = (String) service.getPostConstructorArgs().get("request_method");
    if (!"request".equals(requestMethod) && !"request_uri".equals(requestMethod)) {
      return;
    }
    String algorithm;
    // TODO: Rolands version has secondary input arg "algorithm". Add if needed or remove this
    // comment.
    if (service.getPostConstructorArgs().containsKey("request_object_signing_alg")) {
      algorithm = (String) service.getPostConstructorArgs().get("request_object_signing_alg");
    } else {
      if (service.getServiceContext().getBehavior() != null && service.getServiceContext()
          .getBehavior().getClaims().containsKey("request_object_signing_alg")) {
        algorithm = (String) service.getServiceContext().getBehavior().getClaims()
            .get("request_object_signing_alg");

      } else {
        algorithm = "RS256";
      }
    }
    Key key = null;
    if (!"none".equals(algorithm)) {
      if (service.getPostConstructorArgs().containsKey("key")) {
        key = (Key) service.getPostConstructorArgs().get("key");
      } else {
        String keyType = ServiceUtil.algorithmToKeytypeForJWS(algorithm);
        // TODO: if kid is not in arguments, search for kid in service context or remove this
        // comment if secondary source is not needed.
        String kid = service.getPostConstructorArgs().containsKey("sig_kid")
            ? (String) service.getPostConstructorArgs().get("sig_kid")
            : null;
        Map<String, String> args = new HashMap<String, String>();
        args.put("alg", algorithm);
        List<Key> keys = service.getServiceContext().getKeyJar().getSigningKey(keyType, "", kid,
            args);
        if (keys == null || keys.size() == 0) {
          // TODO: improve error handling, by returning better describing error
          error.getDetails().add(new ErrorDetails("key", ErrorType.MISSING_REQUIRED_VALUE));
          throw new RequestArgumentProcessingException(error);
        }
        key = keys.get(0);
      }
    }
    // Form request object
    Map<String, Object> requestObjectRequestArguments = new HashMap<String, Object>(
        requestArguments);
    // Ensure absence of request and request_uri parameters
    requestObjectRequestArguments.remove("request");
    requestObjectRequestArguments.remove("request_uri");
    RequestObject requestObject = new RequestObject(requestObjectRequestArguments);
    if ("request".equals(requestMethod)) {
      try {
        requestArguments.put("request", requestObject.toJwt(key, algorithm, null, null, null, null, null, null));
      } catch (SerializationException e) {
        // TODO: improve error handling, by returning better describing error
        error.getDetails()
            .add(new ErrorDetails(String.format("Not able to form jwt: '%s'", e.getMessage()),
                ErrorType.VALUE_NOT_ALLOWED));
        throw new RequestArgumentProcessingException(error);
      }
    }
    // TODO: support for request_uri
  }
}
