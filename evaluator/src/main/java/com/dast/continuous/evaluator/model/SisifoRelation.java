package com.dast.continuous.evaluator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SisifoRelation {

    private Map<String, String> arachni;
    private Map<String, String> zap;

    public Map<String, String> getArachni() {
        return arachni;
    }

    public void setArachni(Map<String, String> arachni) {
        this.arachni = arachni;
    }

    public Map<String, String> getZap() {
        return zap;
    }

    public void setZap(Map<String, String> zap) {
        this.zap = zap;
    }
}
