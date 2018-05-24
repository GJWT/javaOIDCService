package org.oidc.services;

import com.auth0.msg.AuthorizationRequest;
import com.auth0.msg.DataLocation;
import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Key;
import com.auth0.msg.Message;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.oidc.common.AddedClaims;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ParameterException;
import org.oidc.common.ValueException;
import org.oidc.service.AbstractService;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.data.StateImpl;
import org.oidc.service.data.StateInterface;
import org.oidc.service.data.StateMap;
import org.oidc.service.util.AlgorithmUtil;
import org.oidc.service.util.Constants;
import org.oidc.service.util.ServiceUtil;

public class Authorization extends org.oauth2.services.Authorization{

    public Authorization(ServiceContext serviceContext,
                         State state,
                         ServiceConfig config) {
        super(serviceContext, state, config);
    }

    public Authorization(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    public void setState(Map<String,String> requestArguments) {
        String state = getAddedClaims().getState().toString();
        if(Strings.isNullOrEmpty(state)) {
            state = requestArguments.get("state");
            if(Strings.isNullOrEmpty(state)) {
                state = RandomStringUtils.randomAlphanumeric(24);
            }
        }

        requestArguments.put("state", state);
        StateInterface stateObject = new StateImpl(this.serviceContext.getIssuer());
        StateMap stateMap = StateMap.getInstance();
        Map<String,State> map = stateMap.getStateMap();
        map.put(state, stateObject);
        //_item = State(iss=self.service_context.issuer)
        //self.state_db.set(_state, _item.to_json())
    }

    public void updateServiceContext(Message response, String stateKey) throws InvalidClaimException, ParameterException, KeyException, JsonProcessingException, SerializationException {
        Message idt = (Message) response.getClaims().get("verifiedIdToken");
        StateImpl state = new StateImpl((String) idt.getClaims().get("iss"));
        if(!(state.getStateKeyByNonce((String) idt.getClaims().get("nonce"))).equals(stateKey)) {
            throw new ParameterException("The 'nonce' has been tampered with");
        }

        if(response.getClaims().containsKey("expiresIn")) {
            response.addClaim("expiresAt", System.currentTimeMillis() + (long) response.getClaims().get("expiresIn"));
        }
        state.storeItem(response, stateKey, MessageType.AUTHORIZATION_RESPONSE);
    }

    public List<Map<String, Object>> oidcPreConstruct(Map<String,Object> requestArguments) throws InvalidClaimException, ValueException {
        if(requestArguments == null) {
            requestArguments = new HashMap<>();
        }

        String responseType = (String) requestArguments.get("responseType");
        Object responseTypes;
        if(Strings.isNullOrEmpty(responseType)) {
            responseTypes = this.serviceContext.getBehavior().getClaims().get("responseTypes");
            if(responseTypes == null) {
                throw new ValueException("responseTypes is null");
            }
            if(!(responseTypes instanceof List)) {
                throw new ValueException("responseTypes is not an instanceof List");
            }
            if(((List) responseTypes).isEmpty()) {
                throw new ValueException("responseTypes is empty");
            }
            responseType = ((List<String>) responseTypes).get(0);
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
        AddedClaims addedClaims = getAddedClaims();
        postArguments.put("requestObjectSigningAlgorithm", addedClaims.getRequestObjectSigningAlgorithm());
        postArguments.put("algorithm", addedClaims.getAlgorithm());
        postArguments.put("sigKid", addedClaims.getSigKid());

        if(Strings.isNullOrEmpty(addedClaims.getRequestMethod())) {
            if("reference".equals(addedClaims.getRequestMethod())) {
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

    public Message oidcPostConstruct(AuthorizationRequest request) throws InvalidClaimException, ValueException, SerializationException, IOException, MissingRequiredAttributeException {
        if(request == null) {
            throw new IllegalArgumentException("null request");
        }

        if(request.getClaims() == null) {
            throw new IllegalArgumentException("null claims");
        }

        Object scope = request.getClaims().get("scope");
        if(scope == null) {
            throw new ValueException("null scope");
        }

        if(scope instanceof List) {
            throw new ValueException("scope isn't an instanceof List");
        }
        String algorithm = "RS256";

        if(((List<String>) scope).contains("openId")) {
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

        AddedClaims addedClaims = getAddedClaims();
        String requestMethod = addedClaims.getRequestMethod();

        if(Strings.isNullOrEmpty(requestMethod)) {

            algorithm = addedClaims.getRequestObjectSigningAlgorithm();
            String tempAlgorithm = addedClaims.getAlgorithm();
            if(!Strings.isNullOrEmpty(tempAlgorithm)) {
                algorithm = tempAlgorithm;
            }

            if (Strings.isNullOrEmpty(algorithm)) {
                algorithm = (String) this.serviceContext.getBehavior().getClaims().get("requestObjectSigningAlg");
                if (Strings.isNullOrEmpty(algorithm)) {
                    algorithm = "RS256";
                }
            }

            setAddedClaims(addedClaims.buildAddedClaimsBuilder().setRequestObjectSigningAlgorithm(algorithm).buildAddedClaims());
        }

        List<Key> keyList = addedClaims.getKeys();
        if(keyList != null && !keyList.isEmpty() && !Strings.isNullOrEmpty(algorithm) && !algorithm.equals("none")) {
            String keyType = AlgorithmUtil.algorithmToKeyType(algorithm);
            String kid = addedClaims.getSigKid();
            if(Strings.isNullOrEmpty(kid)) {
                //_kid = self.service_context.kid["sig"].get(_kty, None)
                //todo: we never added kid to serviceContext
            }

            setAddedClaims(addedClaims.buildAddedClaimsBuilder().setKeys(Arrays.asList(this.serviceContext.getKeyJar().getSigningKey(keyType, kid))).buildAddedClaims());
        }

        Message openIdRequest = ServiceUtil.getOpenIdRequest(request);

        openIdRequest = ServiceUtil.getEncryptedKeys(openIdRequest, this.serviceContext, getAddedClaims());

        if(!Strings.isNullOrEmpty(requestMethod) && "request".equals(requestMethod)) {
            openIdRequest.addClaim("request", openIdRequest);
        } else {
            List<String> webNames = (List<String>) this.serviceContext.getRegistrationResponse().getClaims().get("requestUris");
            if(webNames == null || webNames.isEmpty()) {
                throw new ValueException("null or empty webNames");
            }
            String webName = webNames.get(0);

            String fileName = this.serviceContext.fileNameFromWebname(webName);
            List<String> fileNameAndWebName = null;
            if(Strings.isNullOrEmpty(fileName)) {
                //todo: kwargs isnt even used in python method, so where are local dir and base path being used?
                fileNameAndWebName = ServiceUtil.getRequestUri();
                fileName = fileNameAndWebName.get(0);
                webName = fileNameAndWebName.get(1);
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

    public AddedClaims gatherVerifyArguments() throws InvalidClaimException {
        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder().setClientId(this.serviceContext.getClientId())
                .setIssuer(this.serviceContext.getIssuer()).setKeyJar(this.serviceContext.getKeyJar())
                .setShouldVerify(true).buildAddedClaims();

        for(String key : Constants.IDT2REG.keySet()) {
            //todo: how do we add attributes to addedClaims that are unknown?
            serviceContext.getRegistrationResponse().getClaims().get(Constants.IDT2REG.get(key));
        }

        addedClaims = addedClaims.buildAddedClaimsBuilder().setShouldAllowMissingKid(serviceContext.getAllow().get("missingKid")).buildAddedClaims();
        return addedClaims;
    }

    public Map<String, String> getRedirectUris(Map<String,String> requestArguments, AbstractService service) throws InvalidClaimException, ValueException {
        ServiceContext serviceContext = service.getServiceContext();

        if(!requestArguments.containsKey("redirectUri")) {
            if(serviceContext.getCallBack() != null) {
                String responseType = requestArguments.get("responseType");
                if(Strings.isNullOrEmpty(responseType)) {
                    List<String> responseTypes = (List<String>) serviceContext.getBehavior().getClaims().get("responseTypes");
                    if(responseTypes == null || responseTypes.isEmpty()) {
                        throw new IllegalArgumentException("null or empty responseTypes");
                    }
                    responseType = responseTypes.get(0);
                    requestArguments.put("responseType", responseType);
                }

                String responseMode = requestArguments.get("responseMode");

                if(Strings.isNullOrEmpty(responseMode)) {
                    responseMode = "";
                }

                if("formPost".equals(responseMode)) {
                    requestArguments.put("redirectUri", serviceContext.getCallBack().get(DataLocation.FORM_POST));
                } else if("code".equals(responseMode)) {
                    requestArguments.put("redirectUri", serviceContext.getCallBack().get(DataLocation.CODE));
                } else {
                    requestArguments.put("redirectUri", serviceContext.getCallBack().get(DataLocation.IMPLICIT));
                }
            } else {
                if(serviceContext.getRedirectUris() == null || serviceContext.getRedirectUris().isEmpty()) {
                    throw new ValueException("redirectUris is null or empty");
                }
                requestArguments.put("redirectUri", serviceContext.getRedirectUris().get(0));
            }
        }

        return requestArguments;
    }
}
