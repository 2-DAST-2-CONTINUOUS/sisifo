package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.EntryData;
import com.dast.continuous.evaluator.model.FinalReport;
import com.dast.continuous.evaluator.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class EvaluatorLogicService {
    public FinalReport evaluateToolReports(Map<String, List<Vulnerability>> resultArachni,
                                           Map<String, List<Vulnerability>> resultZap,
                                           EntryData entryData) {

        FinalReport finalReport = new FinalReport();
        if (resultArachni != null) {
            resultArachni.forEach((type, vulnList) -> {

                //finalReport.setName(k);

                System.out.println("Tipo : " + type);

                List<String> urlList = new ArrayList<>();
                for (Vulnerability vuln : vulnList) {
                    //System.out.println(vuln.getEndpoint().getUrl());
                    //System.out.println(vuln.getEndpoint().getMethod());
                    //urlList.add(vuln.getEndpoint().getUrl());
                }
                //repofinalReportrt.setEndpoints(urlList);
                //finalReport.setSeverity("");
            });
        }


        /**
         * Una vez con los resultados de las diferentes tools
         * analizamos con los valores de baremo
         */

        return finalReport;
    }
}
