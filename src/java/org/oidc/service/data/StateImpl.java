package org.oidc.service.data;

import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Message;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.security.KeyException;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.oidc.common.MessageType;
import org.oidc.common.ValueException;

public class StateImpl implements StateInterface{

    private String issuer;

    public StateImpl(String issuer) {
        this.issuer = issuer;
    }

    @Override
    public State getState(String stateKey) throws InvalidClaimException {
        String jsonDoc = StateDB.jsonMap.get(stateKey);
        State state = new State();
        state.fromJson(jsonDoc);
        return state;
    }

    public void setState(String stateKey, State state) throws JsonProcessingException, SerializationException {
        String jsonDoc = state.toJson();
        StateDB.jsonMap.put(stateKey, jsonDoc);
    }

    @Override
    public void storeItem(Message message, String stateKey, MessageType messageType) throws InvalidClaimException, JsonProcessingException, SerializationException {
        State state = getState(stateKey);
        state.addClaim(messageType.name(), message);
        setState(stateKey, state);
    }

    @Override
    public Message getItem(String stateKey, MessageType messageType) throws InvalidClaimException, ValueException {
        State state = getState(stateKey);
        Map<String,Object> claims = state.getClaims();
        Object message = claims.get(messageType.name());
        if(message instanceof Message) {
            return (Message) message;
        } else {
            throw new ValueException("message isn't an instance of Message");
        }
    }

    @Override
    public String getIssuer(String stateKey) throws InvalidClaimException, ValueException {
        State state = getState(stateKey);
        Map<String,Object> claims = state.getClaims();
        Object issuer = claims.get("iss");
        if(issuer instanceof String) {
            return (String) issuer;
        } else {
            throw new ValueException("issuer isn't an instance of String");
        }
    }

    @Override
    public Map<String, Object> extendRequestArgs(Map<String, Object> args, MessageType messageType, String stateKey, List<String> parameters) throws ValueException, InvalidClaimException {
        Message message = this.getItem(stateKey, messageType);
        Map<String,Object> messageClaims = message.getClaims();
        for(String key : messageClaims.keySet()) {
            args.put(key, messageClaims.get(key));
        }

        return args;
    }

    @Override
    public Map<String, Object> multipleExtendRequestArgs(Map<String, Object> args, String stateKey, List<String> parameters, List<MessageType> messageTypes) throws InvalidClaimException, ValueException {
        State state = this.getState(stateKey);
        Map<String,Object> messageClaims;
        Message message;
        Object messageObject;
        for(MessageType messageType : messageTypes) {
            messageObject = state.getClaims().get(messageType);
            if(messageObject  instanceof Message) {
                message = (Message) messageObject;
            } else {
                throw new ValueException("messageObject is not an instance of Message");
            }
            messageClaims = message.getClaims();
            for(String parameter : parameters) {
                args.put(parameter, messageClaims.get(parameter));
            }
        }

        return args;
    }

    @Override
    public void storeStateKeyForNonce(String nonce, String stateKey) {
        StateDB.jsonMap.put("__" + nonce + "__", stateKey);
    }

    @Override
    public String getStateKeyByNonce(String nonce) throws KeyException {
        String stateKey = StateDB.jsonMap.get("__" + nonce + "__");
        if(!Strings.isNullOrEmpty(stateKey)) {
            return stateKey;
        } else {
            throw new KeyException("Unknown nonce: " + nonce);
        }
    }

    @Override
    public String createState(String issuer) throws JsonProcessingException, SerializationException {
        String stateKey = RandomStringUtils.randomAlphanumeric(32);
        State state = new State();
        state.setIssuer(issuer);
        StateDB.jsonMap.put(stateKey, state.toJson());
        return stateKey;
    }
}
