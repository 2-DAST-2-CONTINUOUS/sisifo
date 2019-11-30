package com.dast.continuous.evaluator.service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.dast.continuous.evaluator.model.Endpoint;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.model.arachni.ArachniRaw;
import com.dast.continuous.evaluator.model.arachni.Issue;
import com.dast.continuous.evaluator.utils.Constantes;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ArachniService {

	/**
	 * Añade al mapa "groupVulnerabilities" todas las vulnerabilidades agrupadas 
	 * por el valor del tipo de vulnerabilidad configurado en el parametro "arachniRelations".
	 * 
	 * También se eliminan las url por vulnerabilidad, que coincidan en url y metodo.
	 * 
	 * @param mapData archivo json con los datos obtenidos de la herramienta
	 * @param arachniRelations mapa con la relación entre vulnerabilidades de arachni y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    public void getVulnerabilities(byte[] mapData, Map<String, String> arachniRelations, Map<String, Vulnerability> groupVulnerabilities)
            throws IOException {

        System.out.println("Obteniendo las vulnerabilidades de Arachni");
    	
        ArachniRaw rawData = new ArachniRaw();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ArachniRaw.class);
        } catch (IOException e) {
            System.out.println("Error leyendo JSON");
        }

        List<Issue> issues = rawData.getIssues();

        reduceList(issues, arachniRelations, groupVulnerabilities);        

        System.out.println("Fin obteniendo las vulnerabilidades de Arachni");
    }

    /**
     * Reduce la lista de vulnerabilidades de arachni.
     * 
     * @param issues
     * @param arachniRelations
     * @param groupVulnerabilities
     * @throws MalformedURLException
     */
    private void reduceList(List<Issue> issues, Map<String, String> arachniRelations, 
    		Map<String, Vulnerability> groupVulnerabilities) throws MalformedURLException {

        /**
         * De las vulnerabilidades encontradas las mapeamos a objetos
         * y las agrupamos por tipo de vulnerabilidad y url
         */
        for(Issue issue : issues) {
        	
        	String nameVuln = arachniRelations.get(issue.getCheck().getName());
        	
        	if(StringUtils.isBlank(nameVuln)){
        		
        		Vulnerability vulnerability = new Vulnerability();
        		
        		vulnerability.setName(Constantes.COMMON_MESSAGE_NOT_FOUND + issue.getCheck().getName());
                vulnerability.setShortName(issue.getCheck().getName());
                List<Endpoint> enpoint = new ArrayList<>();
                enpoint.add(issue.getRequest());
                vulnerability.setEndpoint(enpoint);
                vulnerability.setLongName(issue.getName());
                //TODO: Convertir la serveridad
                vulnerability.setSeverity(issue.getSeverity());
                vulnerability.setCwe(issue.getCwe());
                
                groupVulnerabilities.put(vulnerability.getName(), vulnerability);
        		
        	} else if(groupVulnerabilities.containsKey(nameVuln)){
        		
        		Vulnerability vulnerability = groupVulnerabilities.get(nameVuln);        		
        		if(!vulnerability.getEndpoint().stream().anyMatch(obj -> obj.getUrl().equals(issue.getRequest().getUrl()) 
        				&& obj.getMethod().equals(issue.getRequest().getMethod()))){
        			vulnerability.getEndpoint().add(issue.getRequest());
        		}
        		
        	} else {
        		
        		Vulnerability vulnerability = new Vulnerability();
        		
        		vulnerability.setName(nameVuln);
                vulnerability.setShortName(issue.getCheck().getName());
                List<Endpoint> enpoint = new ArrayList<>();
                enpoint.add(issue.getRequest());
                vulnerability.setEndpoint(enpoint);
                vulnerability.setLongName(issue.getName());
                //TODO: Convertir la serveridad
                vulnerability.setSeverity(issue.getSeverity());
                vulnerability.setCwe(issue.getCwe());
                
                groupVulnerabilities.put(vulnerability.getName(), vulnerability);
        		
        	}        	
        }
    }
}
