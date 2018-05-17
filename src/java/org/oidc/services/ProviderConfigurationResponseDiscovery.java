package org.oidc.services;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Jwks;
import com.auth0.msg.ProviderConfigurationResponse;
import com.auth0.msg.RegistrationRequest;
import com.auth0.msg.RegistrationResponse;
import com.google.common.base.Strings;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.ConfigurationException;
import org.oidc.common.OidcServiceException;
import org.oidc.service.AbstractService;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProviderConfigurationResponseDiscovery extends org.oauth2.ProviderConfigurationResponseDiscovery{

    private static final Logger logger = LoggerFactory.getLogger(ProviderConfigurationResponseDiscovery.class);

    public ProviderConfigurationResponseDiscovery(ServiceContext serviceContext,
                                                  State state,
                                                  ProviderConfigResponseDiscoveryServiceConfig config) {
        super(serviceContext, state, config);
    }

    public ProviderConfigurationResponseDiscovery(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    /**
     * This method will run after the response has been parsed and verified.  It requires response
     * in order for the service context to be updated.  This method may update certain attributes
     * of the service context such as issuer, clientId, or clientSecret.  This method does not require
     * a stateKey since it is used for services that are not expected to store state in the state DB.
     *
     * @param response the response as a ProviderConfigurationResponse instance
     */
    public void updateServiceContext(ProviderConfigurationResponse response) throws OidcServiceException, InvalidClaimException, ConfigurationException {
        super.updateServiceContext(response);
        this.matchPreferences(response);
        Jwks jwks;
        if(config.getPreLoadKeys() != null && !config.getPreLoadKeys().isEmpty()) {
            jwks = this.serviceContext.getKeyJar().exportJwksAsJson((String) this.responseMessage.getClaims().get("issuer"));
            logger.info("Preloaded keys for %s: %s", response.getClaims().get("issuer"), jwks.toString());
        }
    }

    /**
     * Gets OIDC url which includes issuer
     * @return OIDC url which includes issuer
     */
    public String getEndpoint() {
        String issuer = this.serviceContext.getIssuer();
        if(Strings.isNullOrEmpty(issuer)) {
            issuer = this.endpointName.name();
        }

        if(issuer.endsWith("/")) {
            issuer = issuer.substring(0,issuer.length()-1);
        }

        return String.format(Constants.OIDC_PATTERN, issuer);
    }

    /**
     * Match the clients preferences against what the provider can do.
     * This is to prepare for later client registration and or what
     * functionality the client actually will use.
     * In the client configuration the client preferences are expressed.
     * These are then compared with the ProviderConfigurationResponse.
     * If the Provider has left some claims out, defaults specified in the
     * standard will be used.
     *
     * @param response
     * @throws ConfigurationException
     * @throws InvalidClaimException
     */
    public void matchPreferences(ProviderConfigurationResponse response) throws ConfigurationException, InvalidClaimException {
        if(response == null) {
            response = this.serviceContext.getProviderConfigurationResponse();
        }

        RegistrationRequest registrationRequest = serviceContext.getConfig().getRegistrationRequest();
        String pcrValues = null;
        Object value;
        for(String key : Constants.PREFERENCE_TO_PROVIDER.keySet()) {
            value = this.serviceContext.getClientPreferences().getClaims().get(key);

            if("tokenEndpointAuthMethod".equals(key)) {
                pcrValues = "clientSecretBasic";
            } else if("idTokenSignedResponseAlg".equals(key)) {
                pcrValues = "RS256";
            }

            Object values = this.serviceContext.getClientPreferences().getClaims().get(key);
            if(values instanceof String) {
                if(pcrValues.contains((String) values)) {
                    Map<String,Object> claims = new HashMap<>();
                    claims.put(key, Constants.PREFERENCE_TO_PROVIDER.get(key));
                    RegistrationResponse registrationResponse = new RegistrationResponse(claims);
                    this.serviceContext.setBehavior(registrationResponse);
                }
            } else {
                Object registrationRequestValue = registrationRequest.getClaims().get(key);
                RegistrationResponse registrationResponse;
                if(values instanceof List) {
                    List<String> listOfValues = (List<String>) values;
                    if (registrationRequestValue instanceof List) {
                        Map<String,Object> claims = new HashMap<>();
                        claims.put(key, null);
                        registrationResponse = new RegistrationResponse(claims);
                        this.serviceContext.setBehavior(registrationResponse);
                        for (Object valueIndex : listOfValues) {
                            if (pcrValues.contains((String) valueIndex)) {
                                claims = new HashMap<>();
                                List<String> listOfValuesFromClaims = (List<String>) claims.get(key);
                                listOfValuesFromClaims.add((String) valueIndex);
                                claims.put(key, listOfValuesFromClaims);
                                registrationResponse = new RegistrationResponse(claims);
                                this.serviceContext.setBehavior(registrationResponse);
                            }
                        }
                    }
                } else {
                    List<String> listOfValues = (List<String>) values;
                    for (Object valueIndex : listOfValues) {
                        if (pcrValues.contains((String) valueIndex)) {
                            Map<String,Object> claims = new HashMap<>();
                            claims.put(key, (String) valueIndex);
                            registrationResponse = new RegistrationResponse(claims);
                            this.serviceContext.setBehavior(registrationResponse);
                        }
                    }
                }

                if(!this.serviceContext.getBehavior().getClaims().containsKey(key)) {
                    throw new ConfigurationException("OP couldn't match preferences: " + key);
                }
            }
        }

        Map<String,Object> claims = this.serviceContext.getClientPreferences().getClaims();
        Object valueFromClaims;
        for(String key : claims.keySet()) {
            valueFromClaims = claims.get(key);
            if(!this.serviceContext.getBehavior().getClaims().containsKey(key)) {
                Object registrationRequestValue = registrationRequest.getClaims().get(key);
                if(registrationRequestValue instanceof List) {
                    List<String> valuesList = (List<String>) registrationRequestValue;
                    valueFromClaims = valuesList.get(0);
                }
            }
            if(!Constants.PREFERENCE_TO_PROVIDER.containsKey(key)) {
                claims = new HashMap<>();
                claims.put(key, valueFromClaims);
                RegistrationResponse registrationResponse = new RegistrationResponse(claims);
                this.serviceContext.setBehavior(registrationResponse);
            }
        }

        logger.debug("ServiceContext behavior: " + this.serviceContext.getBehavior());
    }

}
