package org.oidc.service.util;

import com.auth0.msg.Claims;
import com.auth0.msg.ClaimsRequest;
import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.Jwe;
import com.auth0.msg.Key;
import com.auth0.msg.KeyJar;
import com.auth0.msg.Message;
import com.auth0.msg.OpenIdRequest;
import com.auth0.msg.SerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.oidc.common.AddedClaims;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.services.Authorization;

/**
 * This class has utility methods for various services
 **/
public class ServiceUtil {
    /**
     * Pick out the reference or query part from a URL.
     *
     * @param url a URL possibly containing a query or a reference part
     * @return the query or reference part
     **/
    public static String getUrlInfo(String url) throws MalformedURLException {
        if (Strings.isNullOrEmpty(url)) {
            throw new IllegalArgumentException("null or empty url");
        }
        String queryOrReference = null;

        URL urlObject = new URL(url);
        String query = urlObject.getQuery();
        String reference = urlObject.getRef();

        if (!Strings.isNullOrEmpty(query)) {
            queryOrReference = query;
        } else {
            queryOrReference = reference;
        }

        return queryOrReference;
    }

    /**
     * Serializes the message request to either URL encoded or JSON format.  Will throw an
     * exception if another serialization type is provided.
     *
     * @param request the message request to be serialized
     * @param serializationType the manner in which the request message should be serialized
     * @return the request serialized according to the passed in serialization type
     * @throws UnsupportedSerializationTypeException
     */
    public static String getHttpBody(Message request, SerializationType serializationType) throws UnsupportedSerializationTypeException, JsonProcessingException, SerializationException {
        if (SerializationType.URL_ENCODED.equals(serializationType)) {
            return request.toUrlEncoded();
        } else if (SerializationType.JSON.equals(serializationType)) {
            return request.toJson();
        } else {
            throw new UnsupportedSerializationTypeException("Unsupported serialization type: " + serializationType);
        }
    }

    public static String getState(Map<String,String> requestArguments, ServiceConfig serviceConfig) throws MissingRequiredAttributeException {
        String state = serviceConfig.getState();
        if(Strings.isNullOrEmpty(state)) {
            state = requestArguments.get("state");
            if(Strings.isNullOrEmpty(state)) {
                throw new MissingRequiredAttributeException("state");
            }
        }

        return state;
    }

    public static Message getEncryptedKeys(Message message, ServiceContext serviceContext, AddedClaims addedClaims) throws InvalidClaimException, MissingRequiredAttributeException {
        String encryptionAlgorithm = addedClaims.getRequestObjectEncryptionAlg();
        if(Strings.isNullOrEmpty(encryptionAlgorithm)) {
            encryptionAlgorithm = (String) serviceContext.getBehavior().getClaims().get("requestObjectEncryptionAlg");
        }

        if(Strings.isNullOrEmpty(encryptionAlgorithm)) {
            return message;
        }

        String encryptionEncryption = addedClaims.getRequestObjectEncryptionEnc();
        if(Strings.isNullOrEmpty(encryptionEncryption)) {
            encryptionEncryption = (String) serviceContext.getBehavior().getClaims().get("requestObjectEncryptionEnc");
        }

        if(Strings.isNullOrEmpty(encryptionEncryption)) {
            throw new MissingRequiredAttributeException("No requestObjectEncryptionEnc value specified");
        }

        Jwe jwe = new Jwe(message, encryptionAlgorithm, encryptionEncryption);
        String keyType = AlgorithmUtil.algorithmToKeyType(encryptionAlgorithm);

        String keyId = addedClaims.getEncryptionKid();

        if(Strings.isNullOrEmpty(addedClaims.getTarget())) {
            throw new MissingRequiredAttributeException("No target specified");
        }

        List<Key> keys;
        if(!Strings.isNullOrEmpty(keyId)) {
            keys = serviceContext.getKeyJar().getEncryptionKeys(keyType, addedClaims.getTarget(), keyId);
            jwe.setKeyId(keyId);
        } else {
            keys = serviceContext.getKeyJar().getEncryptionKeys(keyType, addedClaims.getTarget());
        }

        return jwe.encrypt(keys);
    }

    public static Message getOpenIdRequest(Authorization request, KeyJar keyJar, Map<String,Object> userInfoClaims,
                                           Map<String,Object> idTokenClaims, String requestObjectSigningAlg) throws InvalidClaimException {
        Map<String,Object> openIdRequestClaims = new HashMap<>();
        for(String key : new OpenIdRequest().getClaims().keySet()) {
            openIdRequestClaims.put(key, request.getAddedClaims().get);
        }

        for(String attribute : Arrays.asList("scope", "responseType")) {
            if(openIdRequestClaims.containsKey(attribute)) {
                openIdRequestClaims.put(attribute, " " + openIdRequestClaims.get(attribute));
            }
        }

        Map<String,Object> claimsArguments = new HashMap<>();
        if(userInfoClaims != null) {
            claimsArguments.put("userInfo", new Claims(userInfoClaims));
        }
        
        if(idTokenClaims != null) {
            claimsArguments.put("idToken", new Claims(idTokenClaims));
        }
        
        if(claimsArguments != null) {
            openIdRequestClaims.put("claims", new ClaimsRequest(claimsArguments));
        }
        
        OpenIdRequest openIdRequest = new OpenIdRequest(openIdRequestClaims);

        return openIdRequest.toJwt(keyJar, requestObjectSigningAlg);
    }

    public static List<String> getRequestUri(String localDirectoryPath, String basePath) {
        File file = new File(localDirectoryPath);
        if(!file.isDirectory()) {
            file.mkdirs();
        }
        String fileName = RandomStringUtils.randomAlphabetic(10) + ".jwt";
        fileName = localDirectoryPath + "/" + fileName;

        while(file.exists()) {
            fileName = RandomStringUtils.randomAlphabetic(10);
            fileName = localDirectoryPath + "/" + fileName;
            file = new File(fileName);
        }
        String webName = basePath + fileName;
        return Arrays.asList(fileName, webName);
    }
}