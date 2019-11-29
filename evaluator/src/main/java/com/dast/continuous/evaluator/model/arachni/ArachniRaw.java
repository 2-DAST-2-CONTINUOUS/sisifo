package com.dast.continuous.evaluator.model.arachni;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ArachniRaw {

    private String version;
    private String seed;

    private Map<String, Object> options;
    private Map<String, Object> sitemap;
    private String start_datetime;
    private String finish_datetime;
    private List<Issue> issues;
    private Map<String, Object> plugins;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSeed() {
        return seed;
    }

    public void setSeed(String seed) {
        this.seed = seed;
    }

    public String getStartDatetime() {
        return start_datetime;
    }

    public void setStartDatetime(String start_datetime) {
        this.start_datetime = start_datetime;
    }

    public String getFinishDatetime() {
        return finish_datetime;
    }

    public void setFinishDatetime(String finish_datetime) {
        this.finish_datetime = finish_datetime;
    }

    public Map<String, Object> getPlugins() {
        return plugins;
    }

    public void setPlugins(Map<String, Object> plugins) {
        this.plugins = plugins;
    }

    public Map<String, Object> getOptions() {
        return options;
    }

    public void setOptions(Map<String, Object> options) {
        this.options = options;
    }

    public Map<String, Object> getSitemap() {
        return sitemap;
    }

    public void setSitemap(Map<String, Object> sitemap) {
        this.sitemap = sitemap;
    }

    public List<Issue> getIssues() {
        return issues;
    }

    public void setIssues(List<Issue> issues) {
        this.issues = issues;
    }
}
