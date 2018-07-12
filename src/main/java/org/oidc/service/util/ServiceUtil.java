package org.oidc.service.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import java.net.MalformedURLException;
import java.net.URL;
import org.oidc.common.SerializationType;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;

/**
 * This class has utility methods for various services
 **/
public class ServiceUtil {
  /**
   * Pick out the reference or query part from a URL.
   *
   * @param url
   *          a URL possibly containing a query or a reference part
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
   * Serializes the message request to either URL encoded or JSON format. Will throw an exception if
   * another serialization type is provided.
   *
   * @param request
   *          the message request to be serialized
   * @param serializationType
   *          the manner in which the request message should be serialized
   * @return the request serialized according to the passed in serialization type
   * @throws UnsupportedSerializationTypeException
   * @throws SerializationException
   */
  public static String getHttpBody(Message request, SerializationType serializationType)
      throws UnsupportedSerializationTypeException, JsonProcessingException,
      SerializationException {
    if (SerializationType.URL_ENCODED.equals(serializationType)) {
      return request.toUrlEncoded();
    } else if (SerializationType.JSON.equals(serializationType)) {
      return request.toJson();
    } else {
      throw new UnsupportedSerializationTypeException(
          "Unsupported serialization type: " + serializationType);
    }
  }
}