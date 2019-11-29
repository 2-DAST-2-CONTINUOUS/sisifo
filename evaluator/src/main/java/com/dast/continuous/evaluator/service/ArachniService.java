package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.ArachniRaw;
import com.dast.continuous.evaluator.model.Issue;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ArachniService {

    public Map<String, List<Vulnerability>> getVulnerabilities(byte[] mapData) throws MalformedURLException {

        ArachniRaw rawData = new ArachniRaw();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ArachniRaw.class);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.out.println("Error reading JSON");
        }

        List<Issue> issues = rawData.getIssues();
        System.out.println("Issues is: " + issues.size());

        return reduceList(issues);
    }

    private static Map<String, List<Vulnerability>> reduceList(List<Issue> issues) throws MalformedURLException {

        Map<String,List<Vulnerability>> finalResult = new LinkedHashMap<>();
        List<Vulnerability> vulnerabilityList = null;

        // URL ya analizadas
        List<URL> urlUsed = new ArrayList<>();

        /**
         * De las vulnerabilidades encontradas las mapeamos a objetos
         * y las agrupamos por tipo de vulnerabilidad y url
         */
        for(Issue issue : issues) {

            Vulnerability vulnerability = new Vulnerability();

            vulnerability.setShortName(issue.getCheck().getName());
            vulnerability.setUrl(issue.getRequest().getUrl());
            vulnerability.setLongName(issue.getName());
            vulnerability.setSeverity(issue.getSeverity());
            vulnerability.setCwe(issue.getCwe());

            String key = vulnerability.getShortName();

            /**
             * Comprobamos si existen en el map final
             */
            if (!finalResult.containsKey(key)) {
                vulnerabilityList = new ArrayList<>();
                vulnerabilityList.add(vulnerability);
                finalResult.put(key, vulnerabilityList);

                // la añadimos al listado de ya analizadas
                urlUsed.add(new URL(vulnerability.getUrl()));
            } else {

                /**
                 * Si existe se comprueba que no repiten en el mismo endpoint
                 */
                URL url = new URL(vulnerability.getUrl());
                if(!urlUsed.contains(url)) {
                    vulnerabilityList = finalResult.get(key);
                    finalResult.put(key, vulnerabilityList);
                    urlUsed.add(new URL(vulnerability.getUrl()));
                }
            }

        }

        return finalResult;
    }
}
