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

package org.oidc.service.oauth2;

import java.io.IOException;
import java.security.KeyException;
import java.util.Arrays;
import java.util.Map;

import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.KeyJar;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

public class ProviderInfoDiscovery extends AbstractService {

  public ProviderInfoDiscovery(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.PROVIDER_INFO_DISCOVERY;
    this.responseMessage = new ASConfigurationResponse();
    this.expectedResponseClass = ASConfigurationResponse.class;
  }

  @Override
  protected ServiceConfig getDefaultServiceConfig() {
    ServiceConfig defaultConfig = new ServiceConfig();
    defaultConfig.setHttpMethod(HttpMethod.GET);
    defaultConfig.setDeSerializationType(SerializationType.JSON);
    return defaultConfig;
  }
  
  /** {@inheritDoc} */
  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, InvalidClaimException {
    if (stateKey != null) {
      throw new UnsupportedOperationException(
          "stateKey is not supported to update service context" + " for this service");
    }
    String ctxIssuer = getServiceContext().getIssuer();
    if (ctxIssuer == null) {
      throw new MissingRequiredAttributeException("Service context is missing 'issuer'");
    }
    Map<String, Object> pcrClaims = ((ASConfigurationResponse) response).getClaims();
    String pcrIssuer = (String) pcrClaims.get("issuer");
    String issuer;
    if (pcrIssuer.endsWith("/")) {
      if (ctxIssuer.endsWith("/")) {
        issuer = ctxIssuer;
      } else {
        issuer = ctxIssuer + "/";
      }
    } else {
      issuer = ctxIssuer.replaceAll("/\\s*$", "");
    }
    if (getServiceContext().getAllow() != null
        && getServiceContext().isAllowed(Constants.ALLOW_PARAM_ISSUER_MISMATCH)) {
      // mismatches are allowed, nothing to check
    } else {
      if (!issuer.equals(pcrIssuer)) {
        throw new InvalidClaimException(
            "Provider info issuer mismatch " + pcrIssuer + " != " + issuer);
      }
    }
    getServiceContext().setIssuer(pcrIssuer);
    getServiceContext().setProviderConfigurationResponse((ASConfigurationResponse) response);

    for (String pcrKey : pcrClaims.keySet()) {
      EndpointName endpointName = getEndpointName(pcrKey);
      if (endpointName != null) {
        getServiceContext().getEndpoints().put(endpointName, (String) pcrClaims.get(pcrKey));
      }
    }

    KeyJar keyJar = (getServiceContext().getKeyJar() == null) ? new KeyJar()
        : getServiceContext().getKeyJar();
    
    try {
      keyJar.loadKeys(response.getClaims(), issuer, false);
    } catch (KeyException | ImportException | IOException | JWKException | ValueError e) {
      throw new InvalidClaimException(
          String.format("Unable to load keys by jwks or jwks_uri value, '%s'", e.getMessage()));
    }
    // TODO: find out what kind of checks are needed at this point
    getServiceContext().setKeyJar(keyJar);
    
  }

  protected EndpointName getEndpointName(String key) {
    return ImmutableMap.<String, EndpointName>builder()
        .put("authorization_endpoint", EndpointName.AUTHORIZATION)
        .put("registration_endpoint", EndpointName.REGISTRATION)
        .put("token_endpoint", EndpointName.TOKEN)
        .put("revocation_endpoint", EndpointName.REVOCATION)
        .put("introspection_endpoint", EndpointName.INTROSPECTION).build().get(key);
  }

  /**
   * Resolves the OP configuration endpoint by using issuer from either given request arguments,
   * service context or this service object's endpoint variable.
   * 
   * @param requestArguments
   * @return
   * @throws MissingRequiredAttributeException
   *           If the issuer cannot be resolved from the current data.
   */
  protected String getOpEndpoint(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    for (String value : Arrays.asList((String) requestArguments.get("issuer"),
        getServiceContext().getIssuer(), getEndpoint())) {
      if (!Strings.isNullOrEmpty(value)) {
        // remove the trailing '/' if exists from issuer
        return String.format(Constants.OIDCONF_PATTERN, value.replaceAll("/\\s*$", ""));
      }
    }
    throw new RequestArgumentProcessingException(new ErrorDetails("issuer", ErrorType.MISSING_REQUIRED_VALUE, "The value cannot be resolved from the current data"));
  }

  public HttpArguments finalizeGetRequestParameters(HttpArguments httpArguments,
      Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    httpArguments.setUrl(getOpEndpoint(requestArguments));
    return httpArguments;
  }

  @Override
  protected Message doConstructRequest(Map<String, Object> requestArguments)
      throws RequestArgumentProcessingException {
    return null;
  }
}
