package org.oauth2;

import com.auth0.msg.KeyJar;
import com.auth0.msg.Message;
import com.auth0.msg.ProviderConfigurationResponse;
import com.google.common.base.Strings;
import java.util.Map;
import org.oidc.common.HttpMethod;
import org.oidc.common.OidcServiceException;
import org.oidc.common.ServiceName;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;

public class ProviderConfigurationResponseDiscovery extends AbstractService{

    public ProviderConfigurationResponseDiscovery(ServiceContext serviceContext,
                                                  State state,
                                                  ServiceConfig config) {
        super(serviceContext, state, config);
        this.serviceName = ServiceName.PROVIDER_INFO_DISCOVERY;
        //this.requestMessage = ;
        this.responseMessage = new ASConfigurationResponse();
    }

    public ProviderConfigurationResponseDiscovery(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    public HttpArguments getRequestParameters(HttpMethod httpMethod) {
        String issuer = this.serviceContext.getIssuer();

        if(Strings.isNullOrEmpty(issuer)) {
            throw new IllegalArgumentException("null or empty issuer");
        }

        if(issuer.endsWith("/")) {
            issuer = issuer.substring(0, issuer.length()-1);
        }

        HttpArguments httpArguments = new HttpArguments();
        httpArguments.setUrl(String.format(Constants.OIDC_PATTERN, issuer));
        httpArguments.setHttpMethod(httpMethod);

        return httpArguments;
    }

    public HttpArguments getRequestParameters() {
        return getRequestParameters(HttpMethod.GET);
    }

    /**
     * This method will run after the response has been parsed and verified.  It requires response
     * in order for the service context to be updated.  This method may update certain attributes
     * of the service context such as issuer, clientId, or clientSecret.  This method does not require
     * a stateKey since it is used for services that are not expected to store state in the state DB.
     *
     * @param response the response as a ProviderConfigurationResponse instance
     */
    @Override
    public void updateServiceContext(Message response) throws OidcServiceException {
        //todo: should we throw exception if not instance of ProviderConfigurationResponse?
        String issuer = this.serviceContext.getIssuer();

        String issuerFromResponse = (String) response.getClaims().get(Constants.ISSUER);

        if(!Strings.isNullOrEmpty(issuerFromResponse) && !Strings.isNullOrEmpty(issuer)) {
            if(issuerFromResponse.endsWith("/")) {
                if(!issuer.endsWith("/")) {
                    issuer = issuer + "/";
                }
            } else {
                if(issuer.endsWith("/")) {
                    issuer = issuer.substring(0,issuer.length()-1);
                }
            }

            if(!this.serviceContext.getAllow().containsKey("issuerMismatch") && !issuer.equals(issuerFromResponse)) {
                throw new OidcServiceException("Provider config issuer mismatch " + issuer + " != " + issuerFromResponse);
            }

            this.serviceContext.setIssuer(issuerFromResponse);
        } else {
            this.serviceContext.setIssuer(issuer);
        }

        this.serviceContext.setProviderConfigurationResponse((ProviderConfigurationResponse) response);

        ProviderConfigurationResponse pcr = this.serviceContext.getProviderConfigurationResponse();
        Map<String,Object> pcrClaims = pcr.getClaims();
        for(String key : pcrClaims.keySet()) {
            if(!Strings.isNullOrEmpty(key) && key.endsWith("Endpoint")) {
                /* todo
                   for _srv in self.service_context.service.values():
                    if _srv.endpoint_name == key:
                        _srv.endpoint = val
                 */
            }
        }

        KeyJar keyJar = this.serviceContext.getKeyJar();
        if(keyJar == null) {
            keyJar = new KeyJar();
        }

        //todo: where are we loading keys?
        //kj.load_keys(resp, _pcr_issuer)
        this.serviceContext.setKeyJar(keyJar);
    }

    public void updateServiceContext(Message response, String stateKey) {
        throw new UnsupportedOperationException("stateKey is not supported to update service context" +
                " for the WebFinger service");
    }
}
