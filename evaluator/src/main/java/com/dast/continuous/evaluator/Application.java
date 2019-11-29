package com.dast.continuous.evaluator;

import com.dast.continuous.evaluator.model.*;
import com.dast.continuous.evaluator.service.ArachniService;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
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

        Map<String, List<Vulnerability>> result = null;
        try {
            ArachniService arachniService = new ArachniService();
            result = arachniService.getVulnerabilities(mapData);
        } catch (MalformedURLException e) {
            System.out.println(e.getMessage());
        }

        if (result != null) {
            result.forEach((k, v) -> {
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
    	
    }

}
