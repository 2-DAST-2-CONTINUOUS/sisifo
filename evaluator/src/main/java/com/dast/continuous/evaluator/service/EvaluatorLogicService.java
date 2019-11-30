package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.Endpoint;
import com.dast.continuous.evaluator.model.EntryData;
import com.dast.continuous.evaluator.model.FinalReport;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class EvaluatorLogicService {
    public void evaluateToolReports(List<Vulnerability> resultList, EntryData entryData) {

        /**
         * Una vez con los resultados de las diferentes tools
         * analizamos con los valores de baremo
         */
        Map<String, Integer> groupedVulns = new LinkedHashMap<>();
        for (Vulnerability vuln : resultList) {
            String severity = vuln.getSeverity().toLowerCase();

            System.out.println("");
            System.out.println(" * Vulnerabiltiy:" + vuln.getName());
            System.out.println(" * Severity:" + vuln.getSeverity().toLowerCase());
            System.out.println(" * CWE:" + vuln.getCwe());
            System.out.println(" * URLs:");
            for(Endpoint endpoint : vuln.getEndpoint()) {
                System.out.println("    * " + endpoint.getUrl());
            }

            if(!groupedVulns.containsKey(severity)) {
                groupedVulns.put(severity, 1);
            } else {
                Integer cont = groupedVulns.get(severity);
                cont++;
                groupedVulns.put(severity, cont);
            }
            System.out.println("");
            System.out.println("--------------------------------------");
        }

        /***
         * Construimos el DAST Report y lo guardamos en Sistema (/tmp/)
         */
        try {
            this.buildDastReport(resultList);
        } catch (Exception e) {
            System.out.println("Error generating DAST Report");
        }


        /**
         * Recogemos los umbrales de criticidad para valorar si se despliega o no
         */
        Integer criticalParams = entryData.getNumVulnerabilityCritical() == null ? 0 : entryData.getNumVulnerabilityCritical();
        Integer highParams = entryData.getNumVulnerabilityHigh() == null ? 0 : entryData.getNumVulnerabilityHigh();
        Integer mediumParams = entryData.getNumVulnerabilityMedium() == null ? 0 : entryData.getNumVulnerabilityMedium();
        Integer lowParams = entryData.getNumVulnerabilityLow() == null ? 0 : entryData.getNumVulnerabilityLow();

        System.out.println("");
        System.out.println("**************************************");
        System.out.println("**************************************");
        System.out.println("*** Level of Vulnerability Measure ***");
        System.out.println("**************************************");
        System.out.println("**************************************");

        Boolean isKO = Boolean.FALSE;
        for (Map.Entry<String, Integer> entry : groupedVulns.entrySet()) {
            String severity = entry.getKey().toLowerCase();
            Integer value = entry.getValue();
            System.out.println("** "  + severity + " ** | Total : " + value);
            System.out.println("");
            switch (severity) {
                case "critical":
                    if(criticalParams >= value) {
                        isKO = Boolean.TRUE;
                    }
                    break;
                case "high":
                    if(highParams >= value) {
                        isKO = Boolean.TRUE;
                    }
                    break;
                case "medium":
                    if(mediumParams >= value) {
                        isKO = Boolean.TRUE;
                    }
                    break;
                case "low":
                    if(lowParams >= value) {
                        isKO = Boolean.TRUE;
                    }
                    break;
                default:
                    isKO = Boolean.TRUE;
            }
        }
        System.out.println("**************************************");

        /**
         * Evaluamos la respuesta
         */
        if(isKO) {
            System.exit(-1);
        } else {
            System.exit(0);
        }
    }

    /**
     * Construimos DAST Report con la informacion de las Vulnerabilidades encontradas
     * @param resultList
     */
    private void buildDastReport(List<Vulnerability> resultList) throws IOException {

        Map<String, List<Vulnerability>> groupedVulns = new LinkedHashMap<>();
        List<Vulnerability> vulnerabilityList = null;
        for (Vulnerability vuln : resultList) {
            String severity = vuln.getSeverity().toLowerCase();
            if(!groupedVulns.containsKey(severity)) {
                vulnerabilityList = new ArrayList<>();
            } else {
                vulnerabilityList = groupedVulns.get(severity);
            }
            vulnerabilityList.add(vuln);
            groupedVulns.put(severity, vulnerabilityList);
        }

        /*
        System.out.println("");
        System.out.println("*** Starting DAST Report Generation ***");
        System.out.println("--------------------------------------");

        /**
         * Generamos el objeto FinalReport
         */
        /*
        List<FinalReport> dastReport = new ArrayList<>();
        for (Map.Entry<String, List<Vulnerability>> entry : groupedVulns.entrySet()) {
            List<Vulnerability> value = entry.getValue();

            FinalReport finalReport = new FinalReport();
            for(Vulnerability vulnerability : value) {
                finalReport.setName(vulnerability.getName());
                finalReport.setSeverity(vulnerability.getSeverity().toLowerCase());
                finalReport.setDescription(null);
                finalReport.setCwe(vulnerability.getCwe());
                finalReport.setEndpoints(vulnerability.getEndpoint());
            }

            dastReport.add(finalReport);

        }
        */

        ObjectMapper objectMapper = new ObjectMapper();
        resultList.sort(Comparator.comparing(Vulnerability::getSeverity));
        String arrayToJson = objectMapper.writeValueAsString(resultList);

        FileWriter fileWriter = new FileWriter("/tmp/dastreport.json");
        fileWriter.write(arrayToJson);

        System.out.println("");
        System.out.println("*** Saving DAST Report File ***");
        System.out.println("");
        System.out.println("--------------------------------------");

    }
}
