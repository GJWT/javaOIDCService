package org.oidc.service.util;

import com.google.common.base.Strings;
import org.apache.commons.validator.routines.RegexValidator;
import org.oidc.common.ValueException;
import org.apache.commons.validator.routines.UrlValidator;

public class URIUtil {

  private static boolean hasScheme(String url) {
    if (Strings.isNullOrEmpty(url)) {
      throw new IllegalArgumentException("null or empty url");
    }
    if (url.contains("tel:")) {
      String pattern = "tel:\\+[0-9]{10,12}";
      return url.matches(pattern);
    }
    url = url.replaceFirst("@", ".");
    url = url.replaceFirst(".jp", ".com");
    if (url.contains("acct:")) {
      url = url.replaceFirst("acct:", "acct://");
    } else if (url.contains("device:")) {
      url = url.replaceFirst("device:", "device://");
    } else if (url.contains("mailto:")) {
      url = url.replaceFirst("mailto:", "mailto://");
    }
    String[] regexs = { "http", "https", "acct", "device", "mailto" };
    RegexValidator validator = new RegexValidator(regexs, true);
    UrlValidator urlValidator = new UrlValidator(regexs, validator, UrlValidator.ALLOW_ALL_SCHEMES);
    return urlValidator.isValid(url);
  }

  private static boolean isAcctSchemeAssumed(String url) throws ValueException {
    if (url.contains("@")) {
      String[] hostArr = url.split("@");
      if (hostArr != null && hostArr.length > 0) {
        String host = hostArr[hostArr.length - 1];
        if (!Strings.isNullOrEmpty(host)) {
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
    if (hasScheme(url)) {

    } else if (isAcctSchemeAssumed(url)) {
      url = "acct:" + url;
    } else {
      url = "https://" + url;
    }

    return url.split("#")[0];
  }
}
