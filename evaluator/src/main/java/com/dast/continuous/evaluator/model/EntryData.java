package com.dast.continuous.evaluator.model;

public class EntryData {

	private Integer numVulnerabilityCritical;

	private Integer numVulnerabilityHigh;

	private Integer numVulnerabilityMedium;

	private Integer numVulnerabilityLow;
	
	private byte[] arachniResultData;
	
	private byte[] zapResultData;

	public Integer getNumVulnerabilityCritical() {
		return numVulnerabilityCritical;
	}

	public void setNumVulnerabilityCritical(Integer numVulnerabilityCritical) {
		this.numVulnerabilityCritical = numVulnerabilityCritical;
	}

	public Integer getNumVulnerabilityHigh() {
		return numVulnerabilityHigh;
	}

	public void setNumVulnerabilityHigh(Integer numVulnerabilityHigh) {
		this.numVulnerabilityHigh = numVulnerabilityHigh;
	}

	public Integer getNumVulnerabilityMedium() {
		return numVulnerabilityMedium;
	}

	public void setNumVulnerabilityMedium(Integer numVulnerabilityMedium) {
		this.numVulnerabilityMedium = numVulnerabilityMedium;
	}

	public Integer getNumVulnerabilityLow() {
		return numVulnerabilityLow;
	}

	public void setNumVulnerabilityLow(Integer numVulnerabilityLow) {
		this.numVulnerabilityLow = numVulnerabilityLow;
	}

	public byte[] getArachniResultData() {
		return arachniResultData;
	}

	public void setArachniResultData(byte[] arachniResultData) {
		this.arachniResultData = arachniResultData;
	}

	public byte[] getZapResultData() {
		return zapResultData;
	}

	public void setZapResultData(byte[] zapResultData) {
		this.zapResultData = zapResultData;
	}
	
}
