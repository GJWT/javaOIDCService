package org.oidc.service.oauth2;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Map;

import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.common.WebFingerException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oauth2.ASConfigurationResponse;
import org.oidc.service.AbstractService;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.State;
import org.oidc.service.util.Constants;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;

public class ProviderInfoDiscovery extends AbstractService {

  public ProviderInfoDiscovery(ServiceContext serviceContext, State state,
      ServiceConfig serviceConfig) {
    super(serviceContext, state, serviceConfig);
    this.serviceName = ServiceName.PROVIDER_INFO_DISCOVERY;
    this.responseMessage = new ASConfigurationResponse();
    this.httpMethod = HttpMethod.GET;
  }

  @Override
  public void updateServiceContext(Message response, String stateKey) {
    throw new UnsupportedOperationException(
        "stateKey is not supported to update service context" + " for this service");
  }

  @Override
  public void updateServiceContext(Message response)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException {
    if (!(response instanceof ASConfigurationResponse)) {
      throw new ValueException(
          "Unexpected response message type, should be ASConfigurationResponse");
    }
    String ctxIssuer = getServiceContext().getIssuer();
    Map<String, Object> pcrClaims = ((ASConfigurationResponse) response).getClaims();
    String pcrIssuer = (String) pcrClaims.get("issuer");
    String issuer;
    if (pcrIssuer.endsWith("/")) {
      if (ctxIssuer.endsWith("/")) {
        issuer = ctxIssuer;
      } else {
        issuer = ctxIssuer + "/";
      }
    } else {
      issuer = ctxIssuer.replaceAll("/\\s*$", "");
    }
    if (getServiceContext().getAllow() != null
        && getServiceContext().getAllow().get(Constants.ALLOW_PARAM_ISSUER_MISMATCH)) {
      // mismatches are allowed, nothing to check
    } else {
      if (!issuer.equals(pcrIssuer)) {
        throw new InvalidClaimException("Provider info issuer mismatch " + pcrIssuer + " != " + issuer);
      }
    }
    getServiceContext().setIssuer(pcrIssuer);
//    getServiceContext().setProviderConfigurationResponse((ASConfigurationResponse)response);
  }

  protected String getOpEndpoint() throws MissingRequiredAttributeException {
    String issuer = getServiceContext().getIssuer() == null ? getEndpoint()
        : getServiceContext().getIssuer();
    if (Strings.isNullOrEmpty(issuer)) {
      throw new MissingRequiredAttributeException(
          "Issuer cannot be resolved from the current data");
    }
    // remove the trailing '/' if exists from issuer
    return String.format(Constants.OIDCONF_PATTERN, issuer.replaceAll("/\\s*$", ""));
  }

  @Override
  public HttpArguments getRequestParameters(Map<String, String> requestArguments)
      throws UnsupportedSerializationTypeException, JsonProcessingException,
      MissingRequiredAttributeException, MalformedURLException, WebFingerException, ValueException,
      UnsupportedEncodingException, SerializationException, InvalidClaimException {
    HttpArguments httpArguments = super.getRequestParameters(requestArguments);
    httpArguments.setUrl(getOpEndpoint());
    return httpArguments;
  }
}
