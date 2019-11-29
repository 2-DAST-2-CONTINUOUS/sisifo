package com.dast.continuous.evaluator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Issue {

    private String name;
    private String description;
    private List<String> tags;
    private Integer cwe;
    private String severity;
    private Check check;
    private RequestArachni request;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public Integer getCwe() {
        return cwe;
    }

    public void setCwe(Integer cwe) {
        this.cwe = cwe;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Check getCheck() {
        return check;
    }

    public void setCheck(Check check) {
        this.check = check;
    }

    public RequestArachni getRequest() {
        return request;
    }

    public void setRequest(RequestArachni request) {
        this.request = request;
    }
}
