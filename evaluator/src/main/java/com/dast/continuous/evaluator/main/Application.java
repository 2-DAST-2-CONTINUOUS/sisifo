package com.dast.continuous.evaluator.main;

import com.dast.continuous.evaluator.model.SisifoRelation;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.service.ArachniService;
import com.dast.continuous.evaluator.utils.ApplicationProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Inicializador de spring boot
 * 
 * 
 * @author jorge
 *
 */
public class Application {
	
    public static void main( String[] args ) throws IOException, URISyntaxException {

        System.out.println("(^--^) Iniciadando Evaluator (^--^)");

        String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.arachni.filepath");
        String sisifoRelationStr = ApplicationProperties.INSTANCE.getAppName("sisifo.vulnerability.relation");

        SisifoRelation sisifoRelation = getSisifoRelation(sisifoRelationStr);

        Map<String, List<Vulnerability>> result = null;
        try {
            ArachniService arachniService = new ArachniService();
            result = arachniService.getVulnerabilities(resource, sisifoRelation.getArachni());
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
                    System.out.println(vuln.getEndpoint().getUrl());
                    System.out.println(vuln.getEndpoint().getMethod());
                    urlList.add(vuln.getEndpoint().getUrl());

                }
                //report.setOrigin(urlList);
                //report.setSeverity("");
            });
        }
    	
    }

    /**
     * Recuperamos las relaciones parar ponderar las vulnerabilidades
     * @param relationResource
     * @return
     */
    private static SisifoRelation getSisifoRelation(String relationResource) throws URISyntaxException, IOException {

        ///converting json to Map
        byte[] mapData = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(relationResource).toURI()));

        SisifoRelation sisifoRelation = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            sisifoRelation = objectMapper.readValue(mapData, SisifoRelation.class);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.out.println("Error reading JSON");
        }

        return sisifoRelation;
    }

}
