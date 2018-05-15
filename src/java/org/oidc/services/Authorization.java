package org.oidc.services;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Message;
import com.auth0.msg.SerializationException;
import com.google.common.base.Strings;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.oidc.common.AddedClaims;
import org.oidc.common.MessageType;
import org.oidc.common.ParameterException;
import org.oidc.common.ValueException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.AlgorithmUtil;
import org.oidc.service.util.Constants;

public class Authorization extends org.oauth2.services.Authorization{

    public Authorization(ServiceContext serviceContext,
                         State state,
                         ServiceConfig config) {
        super(serviceContext, state, config);
        /**
         *         self.pre_construct = [self.set_state, pick_redirect_uris,
         self.oidc_pre_construct]
         self.post_construct = [self.oidc_post_construct]
         */
    }

    public Authorization(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    public void setState(Map<String,String> requestArguments) {
        String state = serviceConfig.getState();
        if(Strings.isNullOrEmpty(state)) {
            state = requestArguments.get("state");
            if(Strings.isNullOrEmpty(state)) {
                state = RandomStringUtils.randomAlphanumeric(24);
            }
        }

        requestArguments.put("state", state);
        //_item = State(iss=self.service_context.issuer)
        //self.state_db.set(_state, _item.to_json())
    }

    public void updateServiceContext(Message response, String stateKey) throws InvalidClaimException, ParameterException {
        Message idt = (Message) response.getClaims().get("verifiedIdToken");
        State state = getState(stateKey);
        if(!(state.getStateKeyByNonce((String) idt.getClaims().get("nonce"))).equals(stateKey)) {
            throw new ParameterException("The 'nonce' has been tampered with");
        }

        if(response.getClaims().containsKey("expiresIn")) {
            response.addClaim("expiresAt", System.currentTimeMillis() + (long) response.getClaims().get("expiresIn"));
        }
        state.storeItem(response, stateKey, MessageType.AUTHORIZATION_RESPONSE);
    }

    public List<Map<String, Object>> oidcPreConstruct(Map<String,Object> requestArguments) throws InvalidClaimException {
        if(requestArguments == null) {
            requestArguments = new HashMap<>();
        }

        String responseType = (String) requestArguments.get("responseType");
        if(Strings.isNullOrEmpty(responseType)) {
            responseType = ((List<String>) this.serviceContext.getBehavior().getClaims().get("responseTypes")).get(0);
            requestArguments.put("responseType", responseType);
        }

        if(!requestArguments.containsKey("scope")) {
            requestArguments.put("scope", "openId");
        } else if(!((List<String>) requestArguments.get("scope")).contains("openId")) {
            List<String> scope = (List<String>) requestArguments.get("scope");
            scope.add("openId");
            requestArguments.put("scope", scope);
        }

        if(responseType.contains("code") || responseType.contains("idToken")) {
            if(!requestArguments.containsKey("nonce")) {
                requestArguments.put("nonce", RandomStringUtils.randomAlphanumeric(32));
            }
        }

        Map<String,Object> postArguments = new HashMap<>();
        List<String> attributesList = Arrays.asList("requestObjectSigningAlgorithm", "algorithm", "sigKid");
        for(String attribute : attributesList) {
            postArguments.put(attribute, kwargs.get(attribute));
        }

        if(kwargs.containsKey("requestMethod")) {
            if(kwargs.get("requestMethod").equals("reference")) {
                postArguments.put("requestParam", "requestUri");
            } else {
                postArguments.put("requestParam", "request");
            }
        }

        List<Map<String,Object>> listOfArguments = new ArrayList<Map<String, Object>>();
            listOfArguments.add(requestArguments);
        listOfArguments.add(postArguments);

        return listOfArguments;
    }

    public Message oidcPostConstruct(Message request) throws InvalidClaimException, ValueException, SerializationException, IOException {
        String algorithm = "RS256";
        if(((List<String>) request.getClaims().get("scope")).contains("openId")) {
            String responseType = ((List<String>) request.getClaims().get("responseType")).get(0);
            if(!Strings.isNullOrEmpty(responseType) && responseType.contains("idToken") && responseType.contains("code")) {
                String nonce = (String) request.getClaims().get("nonce");
                if(Strings.isNullOrEmpty(nonce)) {
                    nonce = RandomStringUtils.randomAlphanumeric(32);
                    request.addClaim("nonce", nonce);
                }
                //self.store_nonce2state(_nonce, req['state'])
            }
        }

        String requestMethod = kwargs.get("requestMethod");

        if(Strings.isNullOrEmpty(requestMethod)) {

            List<String> arguments = Arrays.asList("requestObjectSigningAlg", "algorithm");
            for (String argument : arguments) {
                algorithm = kwargs.get(argument);
            }

            if (Strings.isNullOrEmpty(algorithm)) {
                algorithm = (String) this.serviceContext.getBehavior().getClaims().get("requestObjectSigningAlg");
                if (Strings.isNullOrEmpty(algorithm)) {
                    algorithm = "RS256";
                }
            }

            kwargs.put("requestObjectSigningAlg", algorithm);
        }

        if(!kwargs.containsKey("keys") && !Strings.isNullOrEmpty(algorithm) && !algorithm.equals("none")) {
            String keyType = AlgorithmUtil.algorithmToKeyType(algorithm);
            String kid = kwargs.get("sigKid");
            if(Strings.isNullOrEmpty(kid)) {
                kid = this.serviceContext.
            }

            kwargs.put("keys", this.serviceContext.getKeyJar().getSigningKey(keyType, kid));
        }

        Message openIdRequest = makeOpenIdRequest(request);

        openIdRequest = requestObjectEncryption(openIdRequest, this.serviceContext);

        if(!Strings.isNullOrEmpty(requestMethod) && "request".equals(requestMethod)) {
            openIdRequest.addClaim("request", openIdRequest);
        } else {
            List<String> webNames = (List<String>) this.serviceContext.getRegistrationResponse().getClaims().get("requestUris");
            if(webNames == null || webNames.isEmpty()) {
                throw new ValueException("null or empty webNames");
            }
            String webName = webNames.get(0);

            String fileName = this.serviceContext.fileNameFromWebname(webName);
            if(Strings.isNullOrEmpty(fileName)) {
                constructRequestUri(getAddedClaims());
            }
            BufferedWriter out = null;
            try
            {
                FileWriter fileStream = new FileWriter(fileName, false);
                out = new BufferedWriter(fileStream);
                out.write(openIdRequest.toJson());
            } finally {
                if(out != null) {
                    out.close();
                }
            }
            request.addClaim("requestUri", webName);
        }

        state.storeItem(request, (String) request.getClaims().get("state"), MessageType.AUTHORIZATION_REQUEST);

        return request;
    }

    public void gatherVerifyArguments() throws InvalidClaimException {
        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder().setClientId(this.serviceContext.getClientId())
                .setIssuer(this.serviceContext.getIssuer()).setKeyJar(this.serviceContext.getKeyJar())
                .setShouldVerify(true).buildAddedClaims();

        for(String key : Constants.IDT2REG.keySet()) {
            //todo: how do we add attributes to addedClaims that are unknown?
            serviceContext.getRegistrationResponse().getClaims().get(Constants.IDT2REG.get(key));
        }

        kwargs.put("allowMissingKid", serviceContext.getAllow().get("missingKid"));
    }
}
