package org.oidc.service.util;

import com.google.common.base.Strings;

public class AlgorithmUtil {

    public static String algorithmToKeyType(String algorithm) {
        if(Strings.isNullOrEmpty(algorithm) || algorithm.toLowerCase().equals("none")) {
            return "none";
        } else if(algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        } else if(algorithm.startsWith("HS") || algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return null;
        }
    }
}
