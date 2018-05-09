package org.oidc.services;

import com.auth0.msg.Key;
import java.util.List;
import java.util.Map;
import org.oidc.common.ClientAuthenticationMethod;
import org.oidc.common.HttpMethod;
import org.oidc.common.SerializationType;
import org.oidc.service.base.ServiceConfig;

public class ProviderConfigResponseDiscoveryServiceConfig extends ServiceConfig{

    private List<Key> preLoadKeys;

    public ProviderConfigResponseDiscoveryServiceConfig(String endpoint, ClientAuthenticationMethod defaultAuthenticationMethod, HttpMethod httpMethod, SerializationType serializationType, SerializationType deSerializationType, Map<String, String> preConstruct, Map<String, String> postConstruct, boolean shouldAllowHttp, boolean shouldAllowNonStandardIssuer
    , List<Key> preLoadKeys) {
        super(endpoint, defaultAuthenticationMethod, httpMethod, serializationType, deSerializationType, preConstruct, postConstruct, shouldAllowHttp, shouldAllowNonStandardIssuer);
        this.preLoadKeys = preLoadKeys;
    }

    public ProviderConfigResponseDiscoveryServiceConfig(boolean shouldAllowHttp, boolean shouldAllowNonStandardIssuer) {
        super(shouldAllowHttp, shouldAllowNonStandardIssuer);
    }

    public List<Key> getPreLoadKeys() {
        return preLoadKeys;
    }
}
