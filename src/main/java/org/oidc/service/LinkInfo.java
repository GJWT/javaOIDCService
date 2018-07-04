package org.oidc.service;

import java.util.Map;

/**
 * One of the attributes of JSON Resource Description (JRD)
 * Contains these attributes: rel, type, href, titles, and properties
 * For more info, please see: https://tools.ietf.org/html/rfc7033#section-4.4.4
 */
public class LinkInfo {

    private String rel;
    private String hRef;
    private String type;
    private Map<String,String> titles;
    private Map<String,String> properties;

    public LinkInfo(String rel, String hRef, String type, Map<String, String> titles, Map<String, String> properties) {
        this.rel = rel;
        this.hRef = hRef;
        this.type = type;
        this.titles = titles;
        this.properties = properties;
    }

    public LinkInfo(String rel, String hRef, String type) {
        this.rel = rel;
        this.hRef = hRef;
        this.type = type;
    }

    public String getRel() {
        return rel;
    }

    public void setRel(String rel) {
        this.rel = rel;
    }

    public String gethRef() {
        return hRef;
    }

    public void sethRef(String hRef) {
        this.hRef = hRef;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map<String, String> getTitles() {
        return titles;
    }

    public void setTitles(Map<String, String> titles) {
        this.titles = titles;
    }

    public Map<String,String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String,String> properties) {
        this.properties = properties;
    }
}
