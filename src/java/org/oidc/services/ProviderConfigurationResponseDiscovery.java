package org.oidc.services;

import com.auth0.msg.ProviderConfigurationResponse;
import com.auth0.msg.RegistrationRequest;
import com.google.common.base.Strings;
import java.util.List;
import java.util.Map;
import javax.naming.ConfigurationException;
import org.oidc.common.OidcServiceException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;

public class ProviderConfigurationResponseDiscovery extends org.oauth2.ProviderConfigurationResponseDiscovery{

    public ProviderConfigurationResponseDiscovery(ServiceContext serviceContext,
                                                  State state,
                                                  ServiceConfig config) {
        super(serviceContext, state, config);
        this.responseMessage = new ProviderConfigurationResponse();
    }

    /**
     * This method will run after the response has been parsed and verified.  It requires response
     * in order for the service context to be updated.  This method may update certain attributes
     * of the service context such as issuer, clientId, or clientSecret.  This method does not require
     * a stateKey since it is used for services that are not expected to store state in the state DB.
     *
     * @param response the response as a ProviderConfigurationResponse instance
     */
    public void updateServiceContext(ProviderConfigurationResponse response) throws OidcServiceException, ConfigurationException {
        super.updateServiceContext(response);
        this.matchPreferences(response);
        //TODO: Roland
        //if 'pre_load_keys' in self.conf and self.conf['pre_load_keys']: {
            this.serviceContext.getKeyJar().exportsJwksAsJson(this.responseMessage.getClaims().get("issuer"))

    }

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

    public void matchPreferences(ProviderConfigurationResponse response) throws ConfigurationException {
        if(response == null) {
            response = this.serviceContext.getProviderConfigurationResponse();
        }

        //todo: how are we going to add the claims with this current implementation?
        RegistrationRequest registrationRequest = new RegistrationRequest();
        String pcrValues = null;
        for(String key : Constants.PREFERENCE_TO_PROVIDER.keySet()) {
            values = this.serviceContext.getClientPreferences().getClaims().get(key);

            if("tokenEndpointAuthMethod".equals(key)) {
                pcrValues = "clientSecretBasic";
            } else if("idTokenSignedResponseAlg".equals(key)) {
                pcrValues = "RS256";
            }

            if(pcrValues == null) {
                if(this.serviceContext.get) {
                    throw new ConfigurationException("OP couldn't match preferences: " + key);
                }
            }

            Object values = this.serviceContext.getClientPreferences().getClaims().get(key);
            if(values instanceof String) {
                if(pcrValues.contains((String) values)) {
                    this.serviceContext.setBehavior();
                }
            } else {
                registrationRequest.getClaims().get(key);
            }
        }

        Map<String,Object> claims = this.serviceContext.getClientPreferences().getClaims();
        for(String key : claims.keySet()) {
            if(!this.serviceContext.getBehavior().getClaims().containsKey(key)) {
                registrationRequest.getClaims().get(key);
            }
        }
    }

}
