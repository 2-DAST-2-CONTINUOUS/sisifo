package com.dast.continuous.evaluator.model;

import java.util.List;

public class FinalReport {

    private String name;
    private List<Endpoint> endpoints;
    private String severity;
    private String description;
    private Integer cwe;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public List<Endpoint> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<Endpoint> endpoints) {
        this.endpoints = endpoints;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getCwe() {
        return cwe;
    }

    public void setCwe(Integer cwe) {
        this.cwe = cwe;
    }
}
