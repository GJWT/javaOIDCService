package org.oidc.service.oidc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.oidc.common.AddedClaims;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.ProviderConfigurationResponse;
import org.oidc.msg.RegistrationRequest;
import org.oidc.msg.RegistrationResponse;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;

import com.google.common.collect.ImmutableMap;

public class ProviderInfoDiscovery extends org.oidc.service.oauth2.ProviderInfoDiscovery {

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
    // TODO: where do we need this?
    this.setAddedClaims(new AddedClaims.AddedClaimsBuilder().buildAddedClaims());
  }

  @Override
  public void updateServiceContext(Message response, String stateKey) {
    throw new UnsupportedOperationException(
        "stateKey is not supported to update service context" + " for this service");
  }

  @Override
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    super.updateServiceContext(response);
    if (getServiceContext().getBehavior() == null) {
      getServiceContext().setBehavior(new RegistrationResponse());
    }
    matchPreferences(response);

    // TODO: implement the following:
    /*
     * if 'pre_load_keys' in self.conf and self.conf['pre_load_keys']: _jwks =
     * self.service_context.keyjar.export_jwks_as_json( issuer=resp['issuer']) logger.info(
     * 'Preloaded keys for {}: {}'.format(resp['issuer'], _jwks))
     */
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
  protected void matchPreferences(Message response) throws MissingRequiredAttributeException {
    ProviderConfigurationResponse pcr;
    if (response == null || !(response instanceof ProviderConfigurationResponse)) {
      if (!(getServiceContext()
          .getProviderConfigurationResponse() instanceof ProviderConfigurationResponse)) {
        throw new MissingRequiredAttributeException(
            "ProviderConfigurationResponse not found in neither response nor service context");
      }
      pcr = (ProviderConfigurationResponse) this.serviceContext.getProviderConfigurationResponse();
    } else {
      pcr = (ProviderConfigurationResponse) response;
    }
    RegistrationRequest preferences = this.getServiceContext().getClientPreferences();
    if (preferences == null) {
      return;
    }
    for (Entry<String, String> entry : PREFERENCE_TO_PROVIDER.entrySet()) {
      String preferenceKey = entry.getKey();
      String providerKey = entry.getValue();
      Object preferenceValue = preferences.getClaims().get(preferenceKey);
      if (preferenceValue == null) {
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
      if (stringOrListContains(preferenceValue, providerValue)) {
        getServiceContext().getBehavior().addClaim(preferenceKey, providerValue);
      } else {
        if (providerValue instanceof List) {
          if (preferenceValue instanceof List) {
            this.getServiceContext().getBehavior().addClaim(preferenceKey, new ArrayList<Object>());
            for (Object item : (List<?>) preferenceValue) {
              if (((List<?>) providerValue).contains(item)) {
                List<Object> list = (List<Object>) this.getServiceContext().getBehavior()
                    .getClaims().get(preferenceKey);
                list.add(item);
                this.getServiceContext().getBehavior().addClaim(preferenceKey, list);
              }
            }
          } else {
            if (((List<?>) providerValue).contains(preferenceValue)) {
              this.getServiceContext().getBehavior().addClaim(preferenceKey,
                  Arrays.asList(preferenceValue));
            }
          }
        } else {
          if (preferenceValue instanceof List)
            if (((List<Object>) preferenceValue).contains(providerValue)) {
              this.getServiceContext().getBehavior().addClaim(preferenceKey, providerValue);
          } else {
            if (preferenceValue.equals(providerValue)) {
              this.getServiceContext().getBehavior().addClaim(preferenceKey, providerValue);              
            }
          }
        }
      }
      if (!getServiceContext().getBehavior().getClaims().containsKey(preferenceKey)) {
        throw new MissingRequiredAttributeException("Could not match prefence " + preferenceKey);
      }
    }
    for (Entry<String, Object> entry : getServiceContext().getClientPreferences().getClaims().entrySet()) {
      if (getServiceContext().getBehavior().getClaims().containsKey(entry.getKey())) {
        continue;
      }
      //TODO: should we support list in preferences even if the registration response data model does not
      //support list?
      getServiceContext().getBehavior().getClaims().put(entry.getKey(), entry.getValue());
    }
  }

  private boolean stringOrListContains(Object value, Object target) {
    if (!(value instanceof String) || target == null) {
      return false;
    }
    if (target instanceof String) {
      return ((String) value).equals((String) target);
    }
    if (target instanceof List) {
      List<?> list = (List<?>) target;
      if (list.isEmpty() || !(list.get(0) instanceof String)) {
        return false;
      }
      return ((List<String>) list).contains((String) value);
    }
    return false;
  }

}
