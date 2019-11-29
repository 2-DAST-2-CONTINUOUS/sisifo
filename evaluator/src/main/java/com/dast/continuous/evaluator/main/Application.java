package com.dast.continuous.evaluator.main;

import com.dast.continuous.evaluator.model.SisifoRelation;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.service.ArachniService;
import com.dast.continuous.evaluator.service.SisifoRelationService;
import com.dast.continuous.evaluator.service.ZapService;
import com.dast.continuous.evaluator.utils.ApplicationProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
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

        System.out.println("(^--^) Inicializando Evaluator (^--^)");

        String sisifoRelationStr = ApplicationProperties.INSTANCE.getAppName("sisifo.vulnerability.relation");

        SisifoRelationService sisifoRelationService = new SisifoRelationService();
        SisifoRelation sisifoRelation = sisifoRelationService.getSisifoRelation(sisifoRelationStr);

        Map<String, List<Vulnerability>> resultArachni = getVulnerabilitiesArachni(sisifoRelation);
        Map<String, List<Vulnerability>> resultZap = getVulnerabilitiesZap(sisifoRelation);
        

        if (resultArachni != null) {
        	resultArachni.forEach((type, vulnList) -> {

                //FinalReport report = new FinalReport();
                //report.setName(k);

                System.out.println("Tipo : " + type);

                List<String> urlList = new ArrayList<>();
                for (Vulnerability vuln : vulnList) {
                    System.out.println(vuln.getEndpoint().getUrl());
                    System.out.println(vuln.getEndpoint().getMethod());
                    urlList.add(vuln.getEndpoint().getUrl());
                }
                //report.setOrigin(urlList);
                //report.setSeverity("");
            });
        }
    	
    }
    
    
    private static Map<String, List<Vulnerability>> getVulnerabilitiesArachni(SisifoRelation sisifoRelation) throws IOException, URISyntaxException {
    	String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.arachni.filepath");
    	Map<String, List<Vulnerability>> result = new HashMap<>();
    	try {
            ArachniService arachniService = new ArachniService();
            result = arachniService.getVulnerabilities(resource, sisifoRelation.getArachni());
        } catch (MalformedURLException e) {
            System.out.println("Fallo en la URL");
        }
    	return result;
    }
    
    
    private static Map<String, List<Vulnerability>> getVulnerabilitiesZap(SisifoRelation sisifoRelation) throws IOException, URISyntaxException {
    	String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.zap.filepath");
    	Map<String, List<Vulnerability>> result = new HashMap<>();
    	try {
            ZapService zapService = new ZapService();
            result = zapService.getVulnerabilities(resource, sisifoRelation.getZap());
        } catch (MalformedURLException e) {
            System.out.println("Fallo en la URL");
        }
    	return result;
    }

}
