package org.oidc.service.util;

import com.auth0.msg.Message;
import com.google.common.base.Strings;
import java.net.MalformedURLException;
import java.net.URL;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedContentType;

/**
 * This class has utility methods for various services
 **/
public class ServiceUtil {
    /**
     Pick out the fragment or query part from a URL.
     * @param url a URL possibly containing a query or a fragment part
     * @return the query/reference part
     **/
    public static String getUrlQueryReference(String url) throws MalformedURLException {
        if(Strings.isNullOrEmpty(url)) {
            throw new IllegalArgumentException("null or empty url");
        }
        String queryOrReference = null;
        if(url.contains("?") && url.contains("#")) {
            URL urlObject = new URL(url);
            String query = urlObject.getQuery();
            String reference = urlObject.getRef();

            if(!Strings.isNullOrEmpty(query)) {
                queryOrReference = query;
            } else {
                queryOrReference = reference;
            }
        }

        return queryOrReference;
    }

    /**
     * Serializes the message request to either URL encoded or JSON format.  Will throw an
     * exception if another serialization type is provided.
     * @param request the message request to be serialized
     * @param serializationType the manner in which the request message should be serialized
     * @return the request serialized according to the passed in serialization type
     * @throws UnsupportedContentType
     */
    public static String getHttpBody(Message request, SerializationType serializationType) throws UnsupportedContentType {
        if(SerializationType.URL_ENCODED.equals(serializationType)) {
            return request.toUrlEncoded();
        } else if(SerializationType.JSON.equals(serializationType)) {
            return request.toJson();
        } else {
            throw new UnsupportedContentType("Unsupported content type: " + serializationType);
        }
    }
}