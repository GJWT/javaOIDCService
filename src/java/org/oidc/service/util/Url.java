package org.oidc.service.util;

/**
 * Copyright 2015 LinkedIn Corp. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 */

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;


/**
 * Creating own Uri class since java.net.Uri would throw parsing exceptions
 * for URL's considered ok by browsers.
 *
 * Also to avoid further conflict, this does stuff that the normal Uri object doesn't do:
 * - Converts http://google.com/a/b/.//./../c to http://google.com/a/c
 * - Decodes repeatedly so that http://host/%2525252525252525 becomes http://host/%25 while normal decoders
 *     would make it http://host/%25252525252525 (one less 25)
 * - Removes tabs and new lines: http://www.google.com/foo\tbar\rbaz\n2 becomes "http://www.google.com/foobarbaz2"
 * - Converts IP addresses: http://3279880203/blah becomes http://195.127.0.11/blah
 * - Strips fragments (anything after #)
 *
 */
public class Url {

    private static final String DEFAULT_SCHEME = "http";
    private static final Map<String, Integer> SCHEME_PORT_MAP;
    static {
        SCHEME_PORT_MAP = new HashMap<String, Integer>();
        SCHEME_PORT_MAP.put("http", 80);
        SCHEME_PORT_MAP.put("https", 443);
        SCHEME_PORT_MAP.put("ftp", 21);
    }
    private UrlMarker _urlMarker;
    private String _scheme;
    private String _originalUrl;

    protected Url(UrlMarker urlMarker) {
        _urlMarker = urlMarker;
        _originalUrl = urlMarker.getOriginalUrl();
    }

    public String getScheme() {
        if (_scheme == null) {
            if (exists(UrlPart.SCHEME)) {
                _scheme = getPart(UrlPart.SCHEME);
                int index = _scheme.indexOf(":");
                if (index != -1) {
                    _scheme = _scheme.substring(0, index);
                }
            } else if (!_originalUrl.startsWith("//")) {
                _scheme = DEFAULT_SCHEME;
            }
        }
        return StringUtils.defaultString(_scheme);
    }

    /**
     * @param urlPart The url part we are checking for existence
     * @return Returns true if the part exists.
     */
    private boolean exists(UrlPart urlPart) {
        return urlPart != null && _urlMarker.indexOf(urlPart) >= 0;
    }

    /**
     * For example, in http://yahoo.com/lala/, nextExistingPart(UrlPart.HOST) would return UrlPart.PATH
     * @param urlPart The current url part
     * @return Returns the next part; if there is no existing next part, it returns null
     */
    private UrlPart nextExistingPart(UrlPart urlPart) {
        UrlPart nextPart = urlPart.getNextPart();
        if (exists(nextPart)) {
            return nextPart;
        } else if (nextPart == null) {
            return null;
        } else {
            return nextExistingPart(nextPart);
        }
    }

    /**
     * @param part The part that we want. Ex: host, path
     */
    private String getPart(UrlPart part) {
        if (!exists(part)) {
            return null;
        }

        UrlPart nextPart = nextExistingPart(part);
        if (nextPart == null) {
            return _originalUrl.substring(_urlMarker.indexOf(part));
        }
        return _originalUrl.substring(_urlMarker.indexOf(part), _urlMarker.indexOf(nextPart));
    }
}
