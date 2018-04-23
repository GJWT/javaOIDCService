package org.oidc.service.util;

import com.google.common.base.Strings;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

public class URIUtil {

    private static boolean hasScheme(String url) {
        if(Strings.isNullOrEmpty(url)) {
            throw new IllegalArgumentException("null or empty url");
        }

        if(url.contains("://")) {
            return true;
        } else {
            String authority = url.replace("/", "#").replace("?", "#")
                    .split("#")[0];

            if(!Strings.isNullOrEmpty(authority) && authority.contains(":")) {
                String[] splitAuthority = authority.split(":", 1);
                if(splitAuthority.length == 2 && !Strings.isNullOrEmpty(splitAuthority[1])
                        && splitAuthority[1].matches("\\d+")) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

    private static boolean isAcctSchemeAssumed(String url) {
        if(Strings.isNullOrEmpty(url)) {
            throw new IllegalArgumentException("null or empty url");
        }

        if(url.contains("@")) {
            String[] hostArr = url.split("@");
            if(hostArr != null && hostArr.length > 0) {
                String host = hostArr[hostArr.length-1];
                if(!Strings.isNullOrEmpty(host)) {
                    return !(host.contains(":") || host.contains("/") || host.contains("?"));
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    public static String normalizeUrl(String url) {
        if(isAcctSchemeAssumed(url)) {
            url = "acct:" + url;
        } else {
            url = "https://" + url;
        }

        return url.split("#")[0];
    }

    public static String urlEncodeUTF8(Map<String,List<String>> map) {
        if(map == null) {
            throw new IllegalArgumentException("null map");
        }
        StringBuilder sb = new StringBuilder();
        String key;
        List<String> values;
        for (Map.Entry<String,List<String>> entry : map.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }

            key = urlEncodeUTF8(entry.getKey().toString());
            values = entry.getValue();

            for(String value : values) {
                sb.append(String.format("%s=%s", key, urlEncodeUTF8(value)));
                sb.append("&");
            }
        }
        if(sb.charAt(sb.length()-1) == '&') {
            sb.deleteCharAt(sb.length()-1);
        }
        return sb.toString();
    }

    private static String urlEncodeUTF8(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException(e);
        }
    }
}
