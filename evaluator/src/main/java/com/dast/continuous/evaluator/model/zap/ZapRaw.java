package com.dast.continuous.evaluator.model.zap;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZapRaw {

    private List<Site> site;

	public List<Site> getSite() {
		return site;
	}

	public void setSite(List<Site> site) {
		this.site = site;
	}
    
}
