package org.oidc.service.util;

import com.google.common.base.Strings;
import org.oidc.common.ValueException;
import org.apache.commons.validator.routines.UrlValidator;

public class URIUtil {

    private static boolean hasScheme(String url) throws ValueException {
        if(Strings.isNullOrEmpty(url)) {
            throw new IllegalArgumentException("null or empty url");
        }

        if(url.contains("://")) {
            return true;
        } else {
            String[] urlArr = url.replace("/", "#").replace("?", "#")
                    .split("#");
            String authority;
            if(urlArr != null && urlArr.length > 0) {
                authority = urlArr[0];
            } else {
                throw new ValueException("Could not properly split url");
            }

            if(!Strings.isNullOrEmpty(authority) && authority.contains(":")) {
                String[] splitAuthority = authority.split(":", 1);
                if(splitAuthority != null && splitAuthority.length == 2 &&
                        !Strings.isNullOrEmpty(splitAuthority[1]) && splitAuthority[1].matches("\\d+")) {
                    return false;
                } else {
                    throw new ValueException("Could not properly split authority");
                }
            } else {
                return false;
            }
        }
    }

    private static boolean isAcctSchemeAssumed(String url) throws ValueException {
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
                throw new ValueException("could not properly split host");
            }
        } else {
            return false;
        }
    }

    public static String normalizeUrl(String url) throws ValueException {
        //will have to use well-tested Java URL libraries
        if(hasScheme(url)) {

        } else if(isAcctSchemeAssumed(url)) {
            url = "acct:" + url;
        } else {
            url = "https://" + url;
        }

        String[] urlSplit = url.split("#");
        if(urlSplit != null && urlSplit.length > 0) {
            return urlSplit[0];
        } else {
            throw new ValueException("could not properly split url");
        }
    }
}
