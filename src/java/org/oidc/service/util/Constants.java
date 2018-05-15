package org.oidc.service.util;

import java.util.HashMap;
import java.util.Map;

public class Constants {
    public static final String OIDC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";
    public static final String WEB_FINGER_URL = "https://%s/.well-known/webfinger";

    /**
     * Claims
     */
    public static final String CLIENT_ID = "clientId";
    public static final String ISSUER = "issuer";
    public static final String KEY_JAR = "keyJar";
    public static final String SHOULD_VERIFY = "shouldVerify";
    public static final String SUBJECT = "subject";
    public static final String LINKS = "links";
    public static final String EXPIRES = "expires";
    public static final String GRANT_TYPE = "grantType";

    public static final Map<String,String> IDT2REG = new HashMap<String,String>() {{
        put("sigalg", "idTokenSignedResponseAlg"); 
        put("encalg", "idTokenEncryptedResponseAlg");
        put("encenc", "idTokenEncryptedResponseEnc");
    }};

}
