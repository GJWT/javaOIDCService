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
import com.google.common.base.Strings;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.oidc.common.ValueException;
import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.InvalidClaimException;
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

  @SuppressWarnings("unchecked")
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
        // For ECDH family we locate our own key
        String keyOwner = alg.startsWith("ECDH") ? "" : service.getServiceContext().getIssuer();
        List<Key> keys = service.getServiceContext().getKeyJar().getEncryptKey(keyType, keyOwner,
            null, args);
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
    String requestObjectJwt;
    try {
      requestObjectJwt = requestObject.toJwt(signingKey, alg, keyTransportKey, encAlg, encEnc,
          service.getServiceContext().getKeyJar(), service.getServiceContext().getIssuer(),
          service.getServiceContext().getClientId());
    } catch (SerializationException e) {
      error.getDetails().add(new ErrorDetails(requestMethod, ErrorType.VALUE_NOT_ALLOWED, 
          "Not able to form jwt", e));
      throw new RequestArgumentProcessingException(error);
    }
    if ("request".equals(requestMethod)) {
      requestArguments.put("request", requestObjectJwt);
    } else {
      // is always request_uri
      Object registeredUri = 
          service.getServiceContext().getBehavior().getClaims().get("request_uris");
      String filename;
      if (registeredUri != null && registeredUri instanceof List && 
          !Strings.isNullOrEmpty(((List<String>) registeredUri).get(0))) {
        String registeredUriStr = ((List<String>) registeredUri).get(0);
        try {
          filename = ServiceUtil.getFilenameFromWebname(service.getServiceContext().getBaseUrl(),
              registeredUriStr);
        } catch (ValueException e) {
          error.getDetails().add(new ErrorDetails("request_uri", 
              ErrorType.VALUE_NOT_ALLOWED, e));
          throw new RequestArgumentProcessingException(error);
        }
        requestArguments.put("request_uri", registeredUriStr);
      } else {
        byte[] randomBytes = new byte[10];
        new SecureRandom(randomBytes);
        String requestDirectory = service.getServiceContext().getRequestsDirectory();
        String uriBase;
        try {
          uriBase = service.getServiceContext().generateRequestUris(requestDirectory).get(0);
        } catch (NoSuchAlgorithmException | ValueException | InvalidClaimException e) {
          error.getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED, 
              "Could not build the base URL for the request_uris", e));
          throw new RequestArgumentProcessingException(error);
        }
        String directory = uriBase.substring(service.getServiceContext().getBaseUrl().length());
        createDirectoryIfNotExist(directory, error);
        filename = directory + "/" + Base64.encodeBase64URLSafeString(randomBytes) + ".jwt";
        requestArguments.put("request_uri", uriBase + filename);
      }
      writeJwtToFile(filename, requestObjectJwt, error);
    }
  }
  
  protected static void createDirectoryIfNotExist(String filename, Error error) 
      throws RequestArgumentProcessingException {
    File file = new File(filename);
    if (!file.exists()) {
      if (!file.mkdir()) {
        error.getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED,
            "Could not create a directory " + filename));
        throw new RequestArgumentProcessingException(error);        
      }
    }
  }
  
  protected static void writeJwtToFile(String filename, String jwt, Error error) 
      throws RequestArgumentProcessingException {
    File file = new File(filename);
    if (file.exists()) {
      if (!file.delete()) {
        error.getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED,
            "Could not delete the existing file for JWT " + filename));
        throw new RequestArgumentProcessingException(error);        
      }
    }
    try {
      file.createNewFile();
    } catch (IOException e) {
      error.getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED,
          "Could not create a file for JWT " + filename, e));
      throw new RequestArgumentProcessingException(error);
    }
    try (FileWriter writer = new FileWriter(file)) {
      writer.write(jwt);
    } catch (IOException e) {
      error.getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED,
          "Could not write JWT to file " + filename, e));
      throw new RequestArgumentProcessingException(error);
    }
  }
}
