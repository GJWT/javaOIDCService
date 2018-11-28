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
    String alg;
    if (service.getPostConstructorArgs().containsKey("request_object_signing_alg")) {
      alg = (String) service.getPostConstructorArgs().get("request_object_signing_alg");
    } else {
      alg = ServiceUtil.getAlgorithmFromBehavior(service, "request_object_signing_alg", 
          "RS256");
    }
    Key signingKey = null;
    if (!"none".equals(alg)) {
      if (service.getPostConstructorArgs().containsKey("key")) {
        signingKey = (Key) service.getPostConstructorArgs().get("key");
      } else {
        String keyType = service.getServiceContext().getKeyJar().algorithmToKeytypeForJWS(alg);
        String kid = service.getPostConstructorArgs().containsKey("sig_kid")
            ? (String) service.getPostConstructorArgs().get("sig_kid")
            : null;
        Map<String, String> args = new HashMap<String, String>();
        args.put("alg", alg);
        List<Key> keys = service.getServiceContext().getKeyJar().getSigningKey(keyType, "", kid,
            args);
        if (keys == null || keys.size() == 0) {
          error.getDetails().add(new ErrorDetails("key", ErrorType.MISSING_REQUIRED_VALUE));
          throw new RequestArgumentProcessingException(error);
        }
        signingKey = keys.get(0);
      }
    }
    String encAlg;
    if (service.getPostConstructorArgs().containsKey("request_object_encryption_alg")) {
      encAlg = (String) service.getPostConstructorArgs().get("request_object_encryption_alg");
    } else {
      encAlg = ServiceUtil.getAlgorithmFromBehavior(service, "request_object_encryption_alg", null);
    }
    Key keyTransportKey = null;
    String encEnc = null;
    if (encAlg != null) {
      if (service.getPostConstructorArgs().containsKey("keytransport_key")) {
        keyTransportKey = (Key) service.getPostConstructorArgs().get("keytransport_key");
      } else {
        String keyType = service.getServiceContext().getKeyJar().algorithmToKeytypeForJWE(alg);
        Map<String, String> args = new HashMap<String, String>();
        args.put("alg", alg);
        List<Key> keys = service.getServiceContext().getKeyJar().getEncryptKey(keyType,
            service.getServiceContext().getIssuer(), null, args);
        if (keys == null || keys.size() == 0) {
          error.getDetails()
              .add(new ErrorDetails("keytransport_key", ErrorType.MISSING_REQUIRED_VALUE));
          throw new RequestArgumentProcessingException(error);
        }
        keyTransportKey = keys.get(0);
      }
      if (service.getPostConstructorArgs().containsKey("request_object_encryption_enc")) {
        encEnc = (String) service.getPostConstructorArgs().get("request_object_encryption_enc");
      } else {
        encEnc = ServiceUtil.getAlgorithmFromBehavior(service, "request_object_encryption_enc",
            null);
      }
      if (encEnc == null) {
        error.getDetails().add(
            new ErrorDetails("request_object_encryption_enc", ErrorType.MISSING_REQUIRED_VALUE));
        throw new RequestArgumentProcessingException(error);
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
        requestArguments.put("request",
            requestObject.toJwt(signingKey, alg, keyTransportKey, encAlg, encEnc,
                service.getServiceContext().getKeyJar(), service.getServiceContext().getIssuer(),
                service.getServiceContext().getClientId()));
      } catch (SerializationException e) {
        error.getDetails()
            .add(new ErrorDetails(String.format("Not able to form jwt: '%s'", e.getMessage()),
                ErrorType.VALUE_NOT_ALLOWED));
        throw new RequestArgumentProcessingException(error);
      }
    }
    // TODO: support for request_uri
  }
}
