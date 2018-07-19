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

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Map;

import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;

import com.auth0.msg.KeyJar;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;

public class ProviderInfoDiscovery extends AbstractService {

  public ProviderInfoDiscovery(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.PROVIDER_INFO_DISCOVERY;
    this.responseMessage = new ASConfigurationResponse();
    this.httpMethod = HttpMethod.GET;
  }

  @Override
  public void updateServiceContext(Message response, String stateKey) {
    throw new UnsupportedOperationException(
        "stateKey is not supported to update service context" + " for this service");
  }

  @Override
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (!(response instanceof ASConfigurationResponse)) {
      throw new ValueException(
          "Unexpected response message type, should be ASConfigurationResponse");
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
        && getServiceContext().getAllow().get(Constants.ALLOW_PARAM_ISSUER_MISMATCH)) {
      // mismatches are allowed, nothing to check
    } else {
      if (!issuer.equals(pcrIssuer)) {
        throw new InvalidClaimException(
            "Provider info issuer mismatch " + pcrIssuer + " != " + issuer);
      }
    }
    getServiceContext().setIssuer(pcrIssuer);
    getServiceContext().setProviderConfigurationResponse((ASConfigurationResponse) response);

    /*
     * TODO: Python code checks if the serviceContext contains any other services and if yes, the
     * endpoints of those services are set to the values defined by _endpoint claims in the response
     * object.
     */

    KeyJar keyJar = (getServiceContext().getKeyJar() == null) ? new KeyJar()
        : getServiceContext().getKeyJar();
    // TODO: load keys from response to KeyJar
    getServiceContext().setKeyJar(keyJar);
  }

  protected String getOpEndpoint() throws MissingRequiredAttributeException {
    String issuer = getServiceContext().getIssuer() == null ? getEndpoint()
        : getServiceContext().getIssuer();
    if (Strings.isNullOrEmpty(issuer)) {
      throw new MissingRequiredAttributeException(
          "Issuer cannot be resolved from the current data");
    }
    // remove the trailing '/' if exists from issuer
    return String.format(Constants.OIDCONF_PATTERN, issuer.replaceAll("/\\s*$", ""));
  }

  @Override
  public HttpArguments getRequestParameters(Map<String, String> requestArguments)
      throws UnsupportedSerializationTypeException, JsonProcessingException,
      MissingRequiredAttributeException, MalformedURLException, WebFingerException, ValueException,
      UnsupportedEncodingException, SerializationException, InvalidClaimException {
    HttpArguments httpArguments = super.getRequestParameters(requestArguments);
    httpArguments.setUrl(getOpEndpoint());
    return httpArguments;
  }
}
