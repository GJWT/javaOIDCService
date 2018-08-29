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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.oidc.common.EndpointName;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.ProviderConfigurationResponse;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.ServiceUtil;

import com.google.common.collect.ImmutableMap;

/**
 * An OIDC provider info discovery service.
 */
public class ProviderInfoDiscovery extends org.oidc.service.oauth2.ProviderInfoDiscovery {

  /**
   * Mappings between client preferences (registration request) and provider capabilities.
   */
  public static final Map<String, String> PREFERENCE_TO_PROVIDER = ImmutableMap
      .<String, String>builder()
      .put("request_object_signing_alg", "request_object_signing_alg_values_supported")
      .put("request_object_encryption_alg", "request_object_encryption_alg_values_supported")
      .put("request_object_encryption_enc", "request_object_encryption_enc_values_supported")
      .put("userinfo_signed_response_alg", "userinfo_signing_alg_values_supported")
      .put("userinfo_encrypted_response_alg", "userinfo_encryption_alg_values_supported")
      .put("userinfo_encrypted_response_enc", "userinfo_encryption_enc_values_supported")
      .put("id_token_signed_response_alg", "id_token_signing_alg_values_supported")
      .put("id_token_encrypted_response_alg", "id_token_encryption_alg_values_supported")
      .put("id_token_encrypted_response_enc", "id_token_encryption_enc_values_supported")
      .put("default_acr_values", "acr_values_supported")
      .put("subject_type", "subject_types_supported")
      .put("token_endpoint_auth_method", "token_endpoint_auth_methods_supported")
      .put("token_endpoint_auth_signing_alg", "token_endpoint_auth_signing_alg_values_supported")
      .put("response_types", "response_types_supported").put("grant_types", "grant_types_supported")
      .build();

  /**
   * The default values for some provider configuration parameters.
   */
  public static final Map<String, String> PROVIDER_DEFAULT = ImmutableMap.<String, String>builder()
      .put("token_endpoint_auth_method", "client_secret_basic")
      .put("id_token_signed_response_alg", "RS256").build();

  public ProviderInfoDiscovery(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.PROVIDER_INFO_DISCOVERY;
    this.requestMessage = null; // no request parameters
    this.responseMessage = new ProviderConfigurationResponse();
    this.httpMethod = HttpMethod.GET;
    this.expectedResponseClass = ProviderConfigurationResponse.class;
  }

  @Override
  protected void doUpdateServiceContext(Message response, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    super.doUpdateServiceContext(response, stateKey);

    if (getServiceContext().getBehavior() == null) {
      getServiceContext().setBehavior(new RegistrationResponse());
    }
    matchPreferences((ProviderConfigurationResponse) response);

    // TODO: the OAuth2 super-class uses KeyJar.loadKeys() -method, but it's functionality is not yet clear
    // TODO: Python has a configuration parameter 'pre_load_keys' for actually downloading the keys
  }

  /**
   * Match the clients preferences against what the provider can do. This is to prepare for later
   * client registration and or what functionality the client actually will use. In the client
   * configuration the client preferences are expressed. These are then compared with the Provider
   * Configuration information. If the Provider has left some claims out, defaults specified in the
   * standard will be used.
   * 
   * @param response
   * @throws MissingRequiredAttributeException
   */
  protected void matchPreferences(ProviderConfigurationResponse pcr)
      throws MissingRequiredAttributeException {
    RegistrationRequest preferences = this.getServiceContext().getClientPreferences();
    if (preferences == null) {
      return;
    }
    for (Entry<String, String> entry : PREFERENCE_TO_PROVIDER.entrySet()) {
      String preferenceKey = entry.getKey();
      String providerKey = entry.getValue();
      Object preferenceValue = preferences.getClaims().get(preferenceKey);
      if (ServiceUtil.nullOrEmptyStringOrList(preferenceValue)) {
        continue;
      }
      Object providerValue = pcr.getClaims().get(providerKey);
      if (providerValue == null) {
        if (PROVIDER_DEFAULT.containsKey(preferenceKey)) {
          providerValue = PROVIDER_DEFAULT.get(preferenceKey);
        } else {
          // TODO: log "no info from provider & no default"
          providerValue = preferenceValue;
        }
      }
      if (providerValue instanceof List) {
        if (preferenceValue instanceof List) {
          List<Object> list = new ArrayList<Object>();
          for (Object item : (List<?>) preferenceValue) {
            if (((List<?>) providerValue).contains(item)) {
              list.add(item);
            }
          }
          if (!list.isEmpty()) {
            this.getServiceContext().getBehavior().addClaim(preferenceKey, list);
          }
        } else {
          if (((List<?>) providerValue).contains(preferenceValue)) {
            this.getServiceContext().getBehavior().addClaim(preferenceKey,
                Arrays.asList(preferenceValue));
          }
        }
      } else {
        if (preferenceValue instanceof List) {
          if (((List<?>) preferenceValue).contains(providerValue)) {
            this.getServiceContext().getBehavior().addClaim(preferenceKey, providerValue);
          }
        } else {
          if (preferenceValue.equals(providerValue)) {
            this.getServiceContext().getBehavior().addClaim(preferenceKey, providerValue);
          }
        }
      }
      if (!getServiceContext().getBehavior().getClaims().containsKey(preferenceKey)) {
        throw new MissingRequiredAttributeException("Could not match prefence " + preferenceKey);
      }
    }
    for (Entry<String, Object> entry : getServiceContext().getClientPreferences().getClaims()
        .entrySet()) {
      if (ServiceUtil.nullOrEmptyStringOrList(entry.getValue())
          || getServiceContext().getBehavior().getClaims().containsKey(entry.getKey())) {
        continue;
      }
      // Note that behaviour may not be valid message as not all client preferences are validated
      // and PCR claims might be list even though request only allows single values.
      getServiceContext().getBehavior().getClaims().put(entry.getKey(), entry.getValue());
    }
  }

  @Override
  protected EndpointName getEndpointName(String key) {
    return ImmutableMap.<String, EndpointName>builder()
        .put("authorization_endpoint", EndpointName.AUTHORIZATION)
        .put("registration_endpoint", EndpointName.REGISTRATION)
        .put("token_endpoint", EndpointName.TOKEN)
        .put("end_session_endpoint", EndpointName.END_SESSION)
        .put("userinfo_endpoint", EndpointName.USER_INFO).build().get(key);
  }
}
