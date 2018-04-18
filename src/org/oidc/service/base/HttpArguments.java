package org.oidc.service.base;

import org.oidc.common.HttpMethod;

/**
 * HttpArguments containing Http method, url, body, and header
 */
public class HttpArguments {

    /**
     * Specifies whether it is a POST or GET request
     */
    private HttpMethod method;
    /**
     * The url of the resource
     */
    private String url;
    /**
     * Used to carry the entity-body associated with the request or response
     * (optional)
     */
    private String body;
    /**
     * Defines the operating parameters of the Http transaction
     */
    private HttpHeader header;

    /**
     * @param method Specifies whether it is a POST or GET request
     * @param url The url of the resource
     * @param body Used to carry the entity-body associated with the request or response
     *             (optional)
     * @param header Defines the operating parameters of the Http transaction
     */
    public HttpArguments(HttpMethod method, String url, String body, HttpHeader header) {

    }

    public HttpArguments(HttpMethod method) {
        this.method = method;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public void setMethod(HttpMethod method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public HttpHeader getHeader() {
        return header;
    }

    public void setHeader(HttpHeader header) {
        this.header = header;
    }
}