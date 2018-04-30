package org.oidc.services;

import com.auth0.msg.Message;
import com.google.common.base.Strings;
import java.net.URL;
import java.org.oidc.common.WebfingerException;
import java.org.oidc.service.data.State;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.util.Constants;
import org.oidc.service.util.URIUtil;

public class Webfinger extends AbstractService {

    /**
     * Message that describes the response.
     */
    Message responseMessage = new JRD();
    /**
     * ServiceName - enum (A name of the service. Later when a RP/client is
     * implemented instances of different services are found by using this name.
     * Default is webFinger)
     */
    ServiceName serviceName = ServiceName.WEB_FINGER;
    /**
     * OIDC issuers
     */
    private List<String> oidcIssuers;

    public Webfinger(ServiceContext serviceContext,
                     State state,
                     ServiceConfig config,
                     List<String> oidcIssuers) {
        super(serviceContext, state, config);
        if (oidcIssuers != null && !oidcIssuers.isEmpty()) {
            this.oidcIssuers = oidcIssuers;
        } else {
            this.oidcIssuers = Arrays.asList(Constants.OIDC_ISSUER);
        }
    }

    public Webfinger(ServiceContext serviceContext) {
        this(serviceContext, null, null, null);
    }

    public Webfinger(ServiceContext serviceContext, List<String> oidcIssuers) {
        this(serviceContext, null, null, oidcIssuers);
    }

    /**
     * This method will run after the response has been parsed and verified.  It requires response
     * in order for the service context to be updated.  This method may update certain attributes
     * of the service context such as issuer, clientId, or clientSecret.  This method does not require
     * a stateKey since it is used for services that are not expected to store state in the state DB.

     * @param response the response as a Message instance
     */
    public void updateServiceContext(Message response) throws MissingRequiredAttributeException {
        List<Link> links = response.getLinks();
        if (links == null || links.isEmpty()) {
            throw new MissingRequiredAttributeException("links is null or empty");
        }

        String href;
        for (Link link : links) {
            if (!Strings.isNullOrEmpty(link.getOidcIssuer()) &&
                    link.getOidcIssuer().equals(this.oidcIssuers)) {
                href = link.getHRef();
                if (!this.getConfig()) {
                    if (!Strings.isNullOrEmpty(href) && href.startsWith("http://") && !isHttpAllowed) {
                        throw new ValueException("http link not allowed: " + href);
                    }
                }
                this.serviceContext.setIssuer(link.getHRef());
                break;
            }
        }
    }

    public void updateServiceContext(Message response, String stateKey) {
        throw new UnsupportedOperationException("stateKey is not required to update service context" +
                "for the WebFinger service");
    }

    public String getQuery(String resource, List<String> oidcIssuers) throws Exception {
        resource = URIUtil.normalizeUrl(resource);

        Map<String, List<String>> queryParams = new LinkedHashMap<String, List<String>>();
        queryParams.put("resource", Arrays.asList(resource));

        if (oidcIssuers == null) {
            if (this.oidcIssuers != null && !this.oidcIssuers.isEmpty()) {
                queryParams.put("oidcIssuers", this.oidcIssuers);
            }
        } else {
            queryParams.put("oidcIssuers", oidcIssuers);
        }

        String host;
        if (Strings.isNullOrEmpty(resource)) {
            throw new IllegalArgumentException("unknown schema");
        } else if (resource.startsWith("http")) {
            URL url = new URL(resource);
            host = url.getHost();
            if (url.getPort() != -1) {
                host += ":" + url.getPort();
            }
        } else if (resource.startsWith("acct:")) {
            String[] hostArr = resource.split("@");
            host = hostArr[hostArr.length - 1].replace("/", "#").replace("?", "#")
                    .split("#")[0];
        } else if (resource.startsWith("device:")) {
            host = resource.split(":")[1];
        } else {
            throw new WebfingerException(resource + " has an unknown schema");
        }

        return String.format(Constants.WEB_FINGER_URL, host) + "?" + URIUtil.urlEncodeUTF8(queryParams);
    }

    public String getQuery(String resource) throws Exception {
        return getQuery(resource, null);
    }

    /**
     * Builds the request message and constructs the HTTP headers.

     This is the starting pont for a pipeline that will:

     - construct the request message
     - add/remove information to/from the request message in the way a
     specific client authentication method requires.
     - gather a set of HTTP headers like Content-type and Authorization.
     - serialize the request message into the necessary format (JSON,
     urlencoded, signed JWT)
     * @param requestArguments
     * @return HttpArguments
     */
    public HttpArguments getRequestParameters(Map<String,String> requestArguments) throws Exception {
        if(requestArguments == null) {
            throw new IllegalArgumentException("null requestArguments");
        }

        String resource = requestArguments.get("resource");
        if(Strings.isNullOrEmpty(resource)) {
            resource = addedClaims.getResource();
            if(Strings.isNullOrEmpty(resource)) {
                resource = this.serviceContext.getConfig().getBaseUrl();
            }
            if(Strings.isNullOrEmpty(resource)) {
                throw new MissingRequiredAttributeExceptionException("resource attribute is missing");
            }
        }

        HttpArguments httpArguments;
        if(!Strings.isNullOrEmpty(addedClaims.getUrl())) {
            httpArguments = new HttpArguments(HttpMethod.GET, this.getQuery(resource, addedClaims.getResource()));
        } else {
            httpArguments = new HttpArguments(HttpMethod.GET, this.getQuery(resource));
        }

        return httpArguments;
    }
}