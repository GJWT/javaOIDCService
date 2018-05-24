package org.oidc.service.data;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.msg.AbstractMessage;
import com.auth0.msg.AuthorizationRequest;
import com.auth0.msg.AuthorizationResponse;
import com.auth0.msg.Error;
import com.auth0.msg.InvalidClaimException;
import com.auth0.msg.KeyJar;
import com.auth0.msg.Message;
import com.auth0.msg.MessageType;
import com.auth0.msg.RefreshTokenRequest;
import com.auth0.msg.RefreshTokenResponse;
import com.auth0.msg.SerializationException;
import com.auth0.msg.TokenResponse;
import com.auth0.msg.UserInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;

public class State extends AbstractMessage {

    private String issuer;
    private AuthorizationRequest authorizationRequest;
    private AuthorizationResponse authorizationResponse;
    private TokenResponse tokenResponse;
    private RefreshTokenRequest refreshTokenRequest;
    private RefreshTokenResponse refreshTokenResponse;
    private UserInfo userInfo;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public AuthorizationResponse getAuthorizationResponse() {
        return authorizationResponse;
    }

    public void setAuthorizationResponse(AuthorizationResponse authorizationResponse) {
        this.authorizationResponse = authorizationResponse;
    }

    public TokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(TokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    public RefreshTokenRequest getRefreshTokenRequest() {
        return refreshTokenRequest;
    }

    public void setRefreshTokenRequest(RefreshTokenRequest refreshTokenRequest) {
        this.refreshTokenRequest = refreshTokenRequest;
    }

    public RefreshTokenResponse getRefreshTokenResponse() {
        return refreshTokenResponse;
    }

    public void setRefreshTokenResponse(RefreshTokenResponse refreshTokenResponse) {
        this.refreshTokenResponse = refreshTokenResponse;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public String toJson() throws SerializationException, JsonProcessingException {
        return null;
    }

    @Override
    public String toUrlEncoded() throws SerializationException, JsonProcessingException {
        return null;
    }

    @Override
    public String toJwt(KeyJar keyJar, Algorithm algorithm) throws SerializationException, JsonProcessingException {
        return null;
    }

    @Override
    public boolean allowCustomClaims() {
        return false;
    }

    @Override
    public void fromJson(String s) throws InvalidClaimException {

    }

    @Override
    public void fromUrlEncoded(String s) throws MalformedURLException, IOException, InvalidClaimException {

    }

    @Override
    public void fromJwt(String s, KeyJar keyJar) {

    }

    @Override
    public void addClaim(String s, Object o) {

    }

    @Override
    protected List<String> getRequiredClaims() {
        return null;
    }

    @Override
    protected MessageType fetchMessageType() {
        return null;
    }

    @Override
    public Map<String, Object> getClaims() throws InvalidClaimException {
        return null;
    }

    @Override
    public Error getError() {
        return null;
    }

    @Override
    public boolean hasError() {
        return false;
    }
}
