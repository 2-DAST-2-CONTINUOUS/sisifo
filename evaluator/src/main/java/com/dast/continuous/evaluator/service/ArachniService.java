package com.dast.continuous.evaluator.service;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;

import com.dast.continuous.evaluator.model.Endpoint;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.model.arachni.ArachniRaw;
import com.dast.continuous.evaluator.model.arachni.Issue;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ArachniService {

    public Map<String, List<Vulnerability>> getVulnerabilities(String resource, Map<String, String> arachniRelations)
            throws IOException, URISyntaxException {

    	InputStream in = ClassLoader.getSystemResourceAsStream(resource);
    	
        ///converting json to Map
        byte[] mapData = IOUtils.toByteArray(in);
    	
        ArachniRaw rawData = new ArachniRaw();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ArachniRaw.class);
        } catch (IOException e) {
            //TODO quitar stackTrace
            System.out.println(e.getMessage());
            System.out.println("Error reading JSON");
        }

        List<Issue> issues = rawData.getIssues();
        System.out.println("Issues is: " + issues.size());

        return reduceList(issues, arachniRelations);
    }

    private static Map<String, List<Vulnerability>> reduceList(List<Issue> issues, Map<String, String> arachniRelations) throws MalformedURLException {

        Map<String,List<Vulnerability>> finalResult = new LinkedHashMap<>();
        List<Vulnerability> vulnerabilityList = null;

        // URL ya analizadas
        List<URL> urlUsed = new ArrayList<>();
        List<String> relationKeys = new ArrayList<>(arachniRelations.keySet());

        /**
         * De las vulnerabilidades encontradas las mapeamos a objetos
         * y las agrupamos por tipo de vulnerabilidad y url
         */
        for(Issue issue : issues) {

            Vulnerability vulnerability = new Vulnerability();

            vulnerability.setShortName(issue.getCheck().getName());
            List<Endpoint> enpoint = new ArrayList<>();
            enpoint.add(issue.getRequest());
            vulnerability.setEndpoint(enpoint);
            vulnerability.setLongName(issue.getName());
            vulnerability.setSeverity(issue.getSeverity());
            vulnerability.setCwe(issue.getCwe());

            String key = vulnerability.getShortName();

            /**
             * Comparamos con las relaciones de JSON
             */
            String arachniRelValue = null;
            if(relationKeys.contains(key)){
                arachniRelValue = arachniRelations.get(key);
            }

            /**
             * Comprobamos si existen en el map final y construimos el report final
             */
            if (!finalResult.containsKey(arachniRelValue)) {
                vulnerabilityList = new ArrayList<>();
                vulnerabilityList.add(vulnerability);

                if(arachniRelValue != null) {
                    finalResult.put(arachniRelValue, vulnerabilityList);
                } else {
                    finalResult.put("Not Defined in Relation JSON", vulnerabilityList);
                }

                /**
                 * Aañadimos al listado de ya analizadas
                 */
                // la añadimos al listado de ya analizadas
                urlUsed.add(new URL(vulnerability.getEndpoint().get(0).getUrl()));
            } else {

                /**
                 * Si existe se comprueba que no repiten en el mismo endpoint
                 */
                URL url = new URL(vulnerability.getEndpoint().get(0).getUrl());
                if(!urlUsed.contains(url)) {
                    vulnerabilityList = finalResult.get(arachniRelValue);
                    finalResult.put(arachniRelValue, vulnerabilityList);
                    urlUsed.add(new URL(vulnerability.getEndpoint().get(0).getUrl()));
                }
            }

        }

        return finalResult;
    }


}
