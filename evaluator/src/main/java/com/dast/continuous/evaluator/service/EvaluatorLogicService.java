package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.EntryData;
import com.dast.continuous.evaluator.model.FinalReport;
import com.dast.continuous.evaluator.model.Vulnerability;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class EvaluatorLogicService {
    public void evaluateToolReports(List<Vulnerability> resultList, EntryData entryData) {

        /**
         * Una vez con los resultados de las diferentes tools
         * analizamos con los valores de baremo
         */
        Map<String, Integer> groupedVulns = new LinkedHashMap<>();
        for (Vulnerability vuln : resultList) {
            System.out.println(vuln.getShortName());
            String severity = vuln.getSeverity();
            if(!groupedVulns.containsKey(severity)) {
                groupedVulns.put(severity, 1);
            } else {
                Integer cont = groupedVulns.get(severity);
                cont++;
                groupedVulns.put(severity, cont);
            }
        }

        groupedVulns.forEach((severity,value)->{
            System.out.println("Item : " + severity + " Count : " + value);
        });

        /**
         * Recogemos los umbrales de criticidad para valorar si se despliega o no
         */
        Integer criticalParams = entryData.getNumVulnerabilityCritical() == null ? 0 : entryData.getNumVulnerabilityCritical();
        Integer highParams = entryData.getNumVulnerabilityHigh() == null ? 0 : entryData.getNumVulnerabilityHigh();
        Integer mediumParams = entryData.getNumVulnerabilityMedium() == null ? 0 : entryData.getNumVulnerabilityMedium();
        Integer lowParams = entryData.getNumVulnerabilityLow() == null ? 0 : entryData.getNumVulnerabilityLow();

        Boolean isKO = Boolean.FALSE;
        for (Map.Entry<String, Integer> entry : groupedVulns.entrySet()) {
            String severity = entry.getKey();
            Integer value = entry.getValue();
            System.out.println("Level of criticality : " + severity + " Count : " + value);
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

        /**
         * Evaluamos la respuesta
         */
        if(isKO) {
            System.exit(-1);
        } else {
            System.exit(0);
        }
    }
}
