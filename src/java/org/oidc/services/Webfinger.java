package org.oidc.services;

import com.auth0.msg.Message;
import com.google.common.base.Strings;
import java.net.URL;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.service.AbstractService;
import org.oidc.service.LinkInfo;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
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
    private static final String linkRelationType = Constants.OIDC_ISSUER;

    public Webfinger(ServiceContext serviceContext,
                     State state,
                     ServiceConfig config) {
        super(serviceContext, state, config);
    }

    public Webfinger(ServiceContext serviceContext) {
        this(serviceContext, null, null);
    }

    /**
     * This method will run after the response has been parsed and verified.  It requires response
     * in order for the service context to be updated.  This method may update certain attributes
     * of the service context such as issuer, clientId, or clientSecret.  This method does not require
     * a stateKey since it is used for services that are not expected to store state in the state DB.
     *
     * @param response the response as a Message instance
     */
    @Override
    public void updateServiceContext(Message response) throws MissingRequiredAttributeException, ValueException {
        List<LinkInfo> links = (List<LinkInfo>) response.getClaims().get("links");
        if (links == null || links.isEmpty()) {
            throw new MissingRequiredAttributeException("links is null or empty");
        }

        String href;
        boolean isHttpAllowed;
        for (LinkInfo link : links) {
            if (!Strings.isNullOrEmpty(link.getRel()) &&
                    link.getRel().equals(linkRelationType)) {
                href = link.gethRef();
                isHttpAllowed = this.getConfig();
                if (!Strings.isNullOrEmpty(href) && href.startsWith("http://") && !isHttpAllowed) {
                    throw new ValueException("http link not allowed: " + href);
                }
                this.serviceContext.setIssuer(link.gethRef());
                //pick the first one
                break;
            }
        }
    }

    public void updateServiceContext(Message response, String stateKey) {
        throw new UnsupportedOperationException("stateKey is not supported to update service context" +
                "for the WebFinger service");
    }

    /**
     * The idea is to retrieve the host and port from the resource and discard other things
     * like path, query, fragment.  The schema can be one of the 3 values: https, acct (when
     * resource looks like email address), device.
     * @param resource
     * @return
     * @throws Exception
     */
    public String getQuery(String resource) throws Exception {
        //two things wrong w resource: no schema or may contain a url fragment and it can't
        //you add a default schema and you remove a url fragment
        resource = URIUtil.normalizeUrl(resource);

        String host;
        if (Strings.isNullOrEmpty(resource)) {
            throw new IllegalArgumentException("unknown schema");
        } else if (resource.startsWith("http")) {
            URL url = new URL(resource);
            host = url.getHost();
            int port = url.getPort();
            if (port != -1) {
                host += ":" + port;
            }
        } else if (resource.startsWith("acct:")) {
            String[] hostArr = resource.split("@");
            if (hostArr != null && hostArr.length > 0) {
                //TODO: see if there are existing libraries that could do this job
                //test with Roland's test input to verify functionality
                //todo: make it a main method and fine tune it (dont work about webfinger)
                String[] hostArrSplit = hostArr[hostArr.length - 1].replace("/", "#").replace("?", "#")
                        .split("#");
                if (hostArrSplit != null && hostArrSplit.length > 0) {
                    host = hostArrSplit[0];
                } else {
                    throw new ValueException("host cannot be split properly");
                }
            } else {
                throw new ValueException("host cannot be split properly");
            }
        } else if (resource.startsWith("device:")) {
            String[] resourceArrSplit = resource.split(":");
            if (resourceArrSplit != null && resourceArrSplit.length > 1) {
                host = resourceArrSplit[1];
            } else {
                throw new ValueException("resource cannot be split properly");
            }
        } else {
            throw new WebFingerException(resource + " has an unknown schema");
        }

        return String.format(Constants.WEB_FINGER_URL, host) + "?" + URIUtil.urlEncodeUTF8(resource);
    }

    /**
     * Builds the request message and constructs the HTTP headers.
     * <p>
     * This is the starting pont for a pipeline that will:
     * <p>
     * - construct the request message
     * - add/remove information to/from the request message in the way a
     * specific client authentication method requires.
     * - gather a set of HTTP headers like Content-type and Authorization.
     * - serialize the request message into the necessary format (JSON,
     * urlencoded, signed JWT)
     *
     * @param requestArguments
     * @return HttpArguments
     */
    @Override
    public HttpArguments getRequestParameters(Map<String, String> requestArguments) throws Exception {
        if (requestArguments == null) {
            throw new IllegalArgumentException("null requestArguments");
        }

        String resource = requestArguments.get("resource");
        AddedClaims addedClaims = getAddedClaims();
        if (Strings.isNullOrEmpty(resource)) {
            resource = addedClaims.getResource();
            if (Strings.isNullOrEmpty(resource)) {
                resource = this.serviceContext.getBaseUrl();
            }
            if (Strings.isNullOrEmpty(resource)) {
                throw new MissingRequiredAttributeException("resource attribute is missing");
            }
        }

        HttpArguments httpArguments;
        if (!Strings.isNullOrEmpty(addedClaims.getUrl())) {
            httpArguments = new HttpArguments(HttpMethod.GET, this.getQuery(resource, addedClaims.getResource()));
        } else {
            httpArguments = new HttpArguments(HttpMethod.GET, this.getQuery(resource));
        }

        return httpArguments;
    }
}