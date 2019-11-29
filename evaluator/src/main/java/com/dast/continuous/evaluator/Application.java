package com.dast.continuous.evaluator;

import com.dast.continuous.evaluator.model.*;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jndi.toolkit.url.Uri;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static java.util.stream.Collectors.groupingBy;

/**
 * Inicializador de spring boot
 * 
 * 
 * @author jorge
 *
 */
public class Application {
	
    public static void main( String[] args ) throws IOException, URISyntaxException {
    	
    	System.out.println("Iniciado");

        String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.arachni.filepath");

        ///converting json to Map
        byte[] mapData = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(resource).toURI()));
        ArachniRaw rawData = new ArachniRaw();

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ArachniRaw.class);
        } catch (JsonMappingException e) {
            System.out.println(e.getMessage());
            System.out.println("Error reading JSON");
        }

        List<Issue> issues = rawData.getIssues();
        System.out.println("Issues is: " + issues.size());

        Map<String, List<Vulnerability>> result = reduceList(issues);

        result.forEach((k,v)->{
            //FinalReport report = new FinalReport();
            //report.setName(k);

            System.out.println("Tipo : " + k + " ---- URL : " + v);

            List<String> urlList = new ArrayList<>();
            for (Vulnerability vuln : v) {
                System.out.println(vuln.getUrl());
                urlList.add(vuln.getUrl());

            }
            //report.setOrigin(urlList);
            //report.setSeverity("");
        });
    	
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
