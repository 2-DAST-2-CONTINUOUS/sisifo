package com.dast.continuous.evaluator.model.zap;

import com.dast.continuous.evaluator.model.Endpoint;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Alert {

    private Long pluginid;
    private String name;
    private Integer riskcode;
    private Integer confidence;
    private String riskdesc;
    private String cweid;
    private List<Endpoint> instances;

    public Long getPluginid() {
        return pluginid;
    }

    public void setPluginid(Long pluginid) {
        this.pluginid = pluginid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getRiskcode() {
        return riskcode;
    }

    public void setRiskcode(Integer riskcode) {
        this.riskcode = riskcode;
    }

    public Integer getConfidence() {
        return confidence;
    }

    public void setConfidence(Integer confidence) {
        this.confidence = confidence;
    }

    public String getRiskdesc() {
        return riskdesc;
    }

    public void setRiskdesc(String riskdesc) {
        this.riskdesc = riskdesc;
    }

	public String getCweid() {
		return cweid;
	}

	public void setCweid(String cweid) {
		this.cweid = cweid;
	}

	public List<Endpoint> getInstances() {
		return instances;
	}

	public void setInstances(List<Endpoint> instances) {
		this.instances = instances;
	}

}
