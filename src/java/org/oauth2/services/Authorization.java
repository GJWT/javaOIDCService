package org.oauth2.services;

import com.auth0.msg.AuthorizationRequest;
import com.auth0.msg.AuthorizationResponse;
import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Message;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.KeyException;
import java.util.List;
import java.util.Map;
import org.oidc.common.EndpointName;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ParameterException;
import org.oidc.common.SerializationType;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.ServiceUtil;

public class Authorization extends AbstractService {

    public Authorization(ServiceContext serviceContext,
                     State state,
                     ServiceConfig config) {
        super(serviceContext, state, config);
        this.serviceName = ServiceName.AUTHORIZATION;
        this.requestMessage = new AuthorizationRequest();
        this.responseMessage = new AuthorizationResponse();
        this.endpointName = EndpointName.AUTHORIZATION;
        this.isSynchronous = false;
        this.deserializationType = SerializationType.URL_ENCODED;
    }

    public Authorization(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    public Authorization(ServiceContext serviceContext, ServiceConfig serviceConfig) {
        this(serviceContext, null, serviceConfig);
    }

    @Override
    public void updateServiceContext(Message response, String stateKey) throws InvalidClaimException, ParameterException, KeyException, JsonProcessingException, SerializationException {
        if(response.getClaims().containsKey("expiresIn")) {
            response.addClaim("expiresAt", System.currentTimeMillis() + (long) response.getClaims().get("expiresIn"));
        }
        //todo: how to get State from stateKey
        State state = getState();
        state.storeItem(responseMessage, stateKey, MessageType.AUTHORIZATION_RESPONSE);
    }

    public void storeAuthorizationRequest(Map<String,String> requestArgs) throws MissingRequiredAttributeException {
        String stateKey = ServiceUtil.getState(requestArgs, getAddedClaims());
        State state = getState();
        state.storeItem(responseMessage, stateKey, MessageType.AUTHORIZATION_REQUEST);
    }

    public HttpArguments getRequestParams(Map<String, String> requestArguments) throws JsonProcessingException, UnsupportedSerializationTypeException, WebFingerException, MalformedURLException, UnsupportedEncodingException, ValueException, MissingRequiredAttributeException, SerializationException {
        HttpArguments httpArguments = super.getRequestParameters(requestArguments);
        List<String> redirectUris;
        if(Strings.isNullOrEmpty(httpArguments.getUrl())) {
            redirectUris = this.serviceContext.getRedirectUris();
            if(redirectUris == null || redirectUris.isEmpty()) {
                throw new ValueException("null or empty redirect uris");
            }
            httpArguments.setUrl(redirectUris.get(0));
        }

        return httpArguments;
    }

    @Override
    public void updateServiceContext(Message response) {
        throw new UnsupportedOperationException("StateKey is required in order to update service context");
    }

    public Message postParseResponse(Message response) throws InvalidClaimException {
        if(response == null) {
            throw new IllegalArgumentException("null response");
        }
        String stateKey = null;
        Message message;
        if(response.getClaims() != null && !response.getClaims().containsKey("scope")) {
            //todo: state comes from where?
            stateKey = serviceConfig.getState();
            if(!Strings.isNullOrEmpty(stateKey)) {
                State state = getState();
                if(state == null) {
                    throw new IllegalArgumentException("null state");
                }
                message = state.getItem(stateKey, MessageType.AUTHORIZATION_REQUEST);
                if(message.getClaims() == null) {
                    throw new IllegalArgumentException("null message claims");
                }
                response.addClaim("scope", message.getClaims().get("scope"));
            }
        }
        return response;
    }
}
