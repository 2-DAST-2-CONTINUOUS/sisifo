package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.SisifoRelation;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.model.arachni.ArachniRaw;
import com.dast.continuous.evaluator.model.arachni.Issue;
import com.dast.continuous.evaluator.model.zap.Alert;
import com.dast.continuous.evaluator.model.zap.Site;
import com.dast.continuous.evaluator.model.zap.ZapInstance;
import com.dast.continuous.evaluator.model.zap.ZapRaw;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ZapService {

    public Map<String, List<Vulnerability>> getVulnerabilities(String resource, Map<String, String> zapRelations)
            throws IOException, URISyntaxException {

        ///converting json to Map
        byte[] mapData = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(resource).toURI()));

        ZapRaw rawData = new ZapRaw();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ZapRaw.class);
        } catch (IOException e) {
            //TODO quitar stackTrace
            System.out.println(e.getMessage());
            System.out.println("Error reading JSON");
        }

        List<Site> sites = rawData.getSite();
        
        for(Site site : sites) {        	
        	System.out.println("alert is: " + site.getAlerts().size());
        }

        Map<String, List<Vulnerability>> result = new HashMap<>();
        return result;
       // return reduceList(instances, zapRelations);
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
            vulnerability.setEndpoint(issue.getRequest());
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
                urlUsed.add(new URL(vulnerability.getEndpoint().getUrl()));
            } else {

                /**
                 * Si existe se comprueba que no repiten en el mismo endpoint
                 */
                URL url = new URL(vulnerability.getEndpoint().getUrl());
                if(!urlUsed.contains(url)) {
                    vulnerabilityList = finalResult.get(arachniRelValue);
                    finalResult.put(arachniRelValue, vulnerabilityList);
                    urlUsed.add(new URL(vulnerability.getEndpoint().getUrl()));
                }
            }

        }

        return finalResult;
    }


}
