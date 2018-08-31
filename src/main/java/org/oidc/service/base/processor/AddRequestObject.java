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
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.msg.Error;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.RequestObject;
import org.oidc.msg.validator.StringClaimValidator;
import org.oidc.service.Service;
import org.oidc.service.base.RequestArgumentProcessingException;

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
 *  
 *  <p>
 * If any of the handled arguments is of wrong type or of unexpected value, processing fails
 * silently.
 * </p>
 */
public class AddRequestObject extends AbstractRequestArgumentProcessor {

  @Override
  protected void processVerifiedArguments(Map<String, Object> requestArguments, Service service,
      Error error) throws RequestArgumentProcessingException {
    
    //TODO: under construction - how to do the validation for post constructor args?
    
    if (requestArguments == null || service == null) {
      return;
    }
    try {

      String requestMethod = new StringClaimValidator()
          .validate(service.getPostConstructorArgs().get("request_method"));

      if (!"request".equals(requestMethod) && !"request_uri".equals(requestMethod)) {
        return;
      }
      // Resolve algorithm
      String algorithm;
      // TODO: Rolands version has secondary input arg "algorithm". Add if needed or remove this
      // comment.
      if (service.getPostConstructorArgs().containsKey("request_object_signing_alg")) {
        algorithm = new StringClaimValidator()
            .validate(service.getPostConstructorArgs().get("request_object_signing_alg"));
      } else {
        if (service.getServiceContext().getBehavior() != null && service.getServiceContext()
            .getBehavior().getClaims().containsKey("request_object_signing_alg")) {
          algorithm = (String) service.getServiceContext().getBehavior().getClaims()
              .get("request_object_signing_alg");

        } else {
          algorithm = "RS256";
        }
      }
      // Resolve keys if algorithm is not none
      Key key = null;
      if (!"none".equals(algorithm)) {
        // primarily from arguments
        if (service.getPostConstructorArgs().containsKey("key")) {
          if (service.getPostConstructorArgs().get("key") instanceof Key) {
            key = (Key) service.getPostConstructorArgs().get("key");
          } else {
            throw new InvalidClaimException("Argument 'key' not of type 'Key'");
          }
        } else {
          String keyType = algorithmToKeytypeForJWS(algorithm);
          // TODO: if kid is not in arguments, search for kid in service context or remove this
          // comment if secondary source is not needed.
          String kid = service.getPostConstructorArgs().containsKey("sig_kid")
              ? new StringClaimValidator().validate(service.getPostConstructorArgs().get("sig_kid"))
              : null;
          Map<String, String> args = new HashMap<String, String>();
          args.put("alg", algorithm);
          // TODO: verify does "" equal to "me"? Correct if not or remove this comment.
          List<Key> keys = service.getServiceContext().getKeyJar().getSigningKey(keyType, "", kid,
              args);
          if (keys == null || keys.size() == 0) {
            throw new MissingRequiredAttributeException(
                "Unable to resolve signing key from key jar");
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
        requestArguments.put("request", requestObject.toJwt(key, algorithm));
      } // else TODO: support for request_uri

      // RO to request arguments or uri handling
    } catch (SerializationException | InvalidClaimException | MissingRequiredAttributeException e) {
      // Indicating exception is not handled on purpose.
      return;
    }
  }

  /**
   * Temporarily here until made public in jawa-jwt.
   * 
   * @param algorithm
   *          algorithm to convert to keytype.
   * @return keytype.
   */
  private String algorithmToKeytypeForJWS(String algorithm) {
    if (algorithm == null || algorithm.toLowerCase().equals("none")) {
      return "none";
    } else if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
      return "RSA";
    } else if (algorithm.startsWith("HS") || algorithm.startsWith("A")) {
      return "oct";
    } else if (algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
      return "EC";
    } else {
      return null;
    }
  }
}
