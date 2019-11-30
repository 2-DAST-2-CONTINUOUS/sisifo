package com.dast.continuous.evaluator.service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.dast.continuous.evaluator.model.Endpoint;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.model.zap.Alert;
import com.dast.continuous.evaluator.model.zap.Site;
import com.dast.continuous.evaluator.model.zap.ZapRaw;
import com.dast.continuous.evaluator.utils.Constantes;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ZapService {

	/**
	 * Añade al mapa "groupVulnerabilities" todas las vulnerabilidades agrupadas 
	 * por el valor del tipo de vulnerabilidad configurado en el parametro "zapRelations".
	 * 
	 * También se eliminan las url por vulnerabilidad, que coincidan en url y metodo.
	 * 
	 * @param mapData archivo json con los datos obtenidos de la herramienta
	 * @param zapRelations mapa con la relación entre vulnerabilidades de zap y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    public void getVulnerabilities(byte[] mapData, Map<String, String> zapRelations, 
    		Map<String, Vulnerability> groupVulnerabilities) throws IOException, URISyntaxException {

        System.out.println("Obteniendo las vulnerabilidades de Zap");

        ZapRaw rawData = new ZapRaw();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            rawData = objectMapper.readValue(mapData, ZapRaw.class);
        } catch (IOException e) {
            System.out.println("Error reading JSON");
        }

        List<Site> sites = rawData.getSite();        
        for (Site site : sites){
	        reduceList(site, zapRelations, groupVulnerabilities);
	    }

        System.out.println("Fin obteniendo las vulnerabilidades de Zap");
    }

    /**
     * Reduce la lista de vulnerabilidades de zap.
     * 
     * @param site
     * @param zapRelations
     * @param groupVulnerabilities
     * @throws MalformedURLException
     */
    private void reduceList(Site site, Map<String, String> zapRelations, 
    		Map<String, Vulnerability> groupVulnerabilities) throws MalformedURLException {
        
        /**
         * De las vulnerabilidades encontradas las mapeamos a objetos
         * y las agrupamos por tipo de vulnerabilidad y url
         */
    	for (Alert alert: site.getAlerts()) {
    		
    		String nameVuln = zapRelations.get(alert.getPluginid());
    		
    		if(StringUtils.isBlank(nameVuln)){
        		
        		Vulnerability vulnerability = new Vulnerability();
        		
        		vulnerability.setName(Constantes.COMMON_MESSAGE_NOT_FOUND + alert.getName());
                vulnerability.setShortName(alert.getName());                
                vulnerability.setLongName(alert.getName());
                //TODO: Convertir la serveridad
                vulnerability.setSeverity(alert.getRiskdesc().replaceAll("\\(.*\\)", "").trim());
                vulnerability.setCwe(Integer.parseInt(alert.getCweid()));
                
                for(Endpoint endPointZap : alert.getInstances()){
                	if(!vulnerability.getEndpoint().stream().anyMatch(obj -> obj.getUrl().equals(getUrlWithoutParameters(endPointZap.getUrl())) 
            				&& obj.getMethod().equals(endPointZap.getMethod()))){                		
            			vulnerability.getEndpoint().add(new Endpoint(endPointZap.getMethod(), getUrlWithoutParameters(endPointZap.getUrl())));
            		}
                }
                
                groupVulnerabilities.put(vulnerability.getName(), vulnerability);
        		
        	} else if(groupVulnerabilities.containsKey(nameVuln)){
        		
        		Vulnerability vulnerability = groupVulnerabilities.get(nameVuln);
        		
        		for(Endpoint endPointZap : alert.getInstances()){
        			if(!vulnerability.getEndpoint().stream().anyMatch(obj -> obj.getUrl().equals(getUrlWithoutParameters(endPointZap.getUrl())) 
            				&& obj.getMethod().equals(endPointZap.getMethod()))){                		
            			vulnerability.getEndpoint().add(new Endpoint(endPointZap.getMethod(), getUrlWithoutParameters(endPointZap.getUrl())));
            		}
                }
        		
        	} else {
        		
        		Vulnerability vulnerability = new Vulnerability();
        		
        		vulnerability.setShortName(alert.getName());                
                vulnerability.setLongName(alert.getName());
                //TODO: Convertir la serveridad
                vulnerability.setSeverity(alert.getRiskdesc().replaceAll("\\(.*\\)", ""));
                vulnerability.setCwe(Integer.parseInt(alert.getCweid()));
                
                for(Endpoint endPointZap : alert.getInstances()){
                	if(!vulnerability.getEndpoint().stream().anyMatch(obj -> obj.getUrl().equals(getUrlWithoutParameters(endPointZap.getUrl())) 
            				&& obj.getMethod().equals(endPointZap.getMethod()))){                		
            			vulnerability.getEndpoint().add(new Endpoint(endPointZap.getMethod(), getUrlWithoutParameters(endPointZap.getUrl())));
            		}
                }
                
                groupVulnerabilities.put(vulnerability.getName(), vulnerability);
        		
        	} 
    		
    	}
    }

    /**
     * Elimina los parametros de la URL
     * 
     * @param url
     * @return
     * @throws URISyntaxException
     */
    private String getUrlWithoutParameters(String url) {
    	try {
        URI uri = new URI(url);
        return new URI(uri.getScheme(),
                       uri.getAuthority(),
                       uri.getPath(),
                       null, // Ignore the query part of the input url
                       uri.getFragment()).toString();
    	} catch(URISyntaxException ex){
    		throw new RuntimeException(ex.getMessage(), ex);
    	}
    }
    
}
