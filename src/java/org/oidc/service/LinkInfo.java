package org.oidc.service;

import java.util.List;

public class LinkInfo {

    private String rel;
    private String hRef;
    private String type;
    private List<String> properties;

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

    public List<String> getProperties() {
        return properties;
    }

    public void setProperties(List<String> properties) {
        this.properties = properties;
    }
}
