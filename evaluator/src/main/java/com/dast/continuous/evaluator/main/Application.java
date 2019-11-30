package com.dast.continuous.evaluator.main;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.dast.continuous.evaluator.model.EntryData;
import com.dast.continuous.evaluator.model.SisifoRelation;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.service.ArachniService;
import com.dast.continuous.evaluator.service.EvaluatorLogicService;
import com.dast.continuous.evaluator.service.SisifoRelationService;
import com.dast.continuous.evaluator.service.ZapService;
import com.dast.continuous.evaluator.utils.ApplicationProperties;

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
        
        String header = "Intefaz por linea de comandos para el evaluador de SISIFO \n\n";
		String footer = "\n";
        
        CommandLineParser parser = null;
		CommandLine cmdLine = null;
        
		Options options = new Options();
		options.addOption("h", "help", false, "Mensaje de ayuda");
		options.addOption("v", "version", false, "Version de la aplicacion");
		
		options.addOption(Option.builder("vc").desc("Num. Vulnerabilidades criticas (Critical)")
				.hasArg().build());
		options.addOption(Option.builder("vh").desc("Num. Vulnerabilidades altas (High)")
				.hasArg().build());
		options.addOption(Option.builder("vm").desc("Num. Vulnerabilidades medias (Medium)")
				.hasArg().build());
		options.addOption(Option.builder("vl").desc("Num. Vulnerabilidades bajas (Low)")
				.hasArg().build());

		options.addOption(Option.builder("fa").desc("Fichero de Arachni")
				.hasArg().build());

		options.addOption(Option.builder("fz").desc("Fichero de Zap")
				.hasArg().build());
		
		if (args.length == 0 
				|| Arrays.stream(args).anyMatch(arg -> arg.equals("-h") || arg.equals("--help"))) {
			new HelpFormatter().printHelp("sisifo-evaluador", header, options, footer,
					true);
			return;
		}
		
		if (Arrays.stream(args).anyMatch(arg -> arg.equals("-v") || arg.equals("--version"))) {
			System.out.println("V 0.0.1");
			return;
		}

		EntryData entryData = null;
		try {

			parser = new DefaultParser();
			cmdLine = parser.parse(options, args);	
			
			entryData = getArgsSisifo(cmdLine);
			
			if(checkNull(entryData)){
				new HelpFormatter().printHelp("sisifo-evaluador", header, options, footer,
						true);
				return;
			}
			
		} catch (ParseException ex) {
			System.out.println(ex.getMessage());
			new HelpFormatter().printHelp("sisifo-evaluador", header, options, footer,
					true);
			return;
		}

		/**
		 * Cargamos el JSON de Vulnerabilidades configuradas por Sisifo para el Match
		 */
		String sisifoRelationStr = ApplicationProperties.INSTANCE.getAppName("sisifo.vulnerability.relation");
        SisifoRelationService sisifoRelationService = new SisifoRelationService();
        SisifoRelation sisifoRelation = sisifoRelationService.getSisifoRelation(sisifoRelationStr);

        Map<String, Vulnerability> groupVulnerabilities = new HashMap<>();
        if (entryData.getArachniResultData() != null) {
        	getVulnerabilitiesArachni(entryData, sisifoRelation, groupVulnerabilities);
        }
        if (entryData.getZapResultData() != null) {
        	getVulnerabilitiesZap(entryData, sisifoRelation, groupVulnerabilities);
        }

        List<Vulnerability> vulnerabilities = new ArrayList<Vulnerability>(groupVulnerabilities.values());
        
		EvaluatorLogicService evaluatorLogicService = new EvaluatorLogicService();
		evaluatorLogicService.evaluateToolReports(vulnerabilities, entryData);
    }
    
    /**
     * Función que obtiene todos los datos de entrada desde la linea de comandos
     * 
     * @param cmdLine comandos desde la linea
     * @return
     * @throws IOException 
     */
    private static EntryData getArgsSisifo(CommandLine cmdLine) throws IOException{
    	
    	EntryData entryData = new EntryData();
    	    	
    	System.out.println("Datos de entrada");	
    	
    	if (cmdLine.hasOption("vc")) {    		
    		Integer numVuln = Integer.parseInt(cmdLine.getOptionValue("vc"));    		
    		entryData.setNumVulnerabilityCritical(numVuln != null ? numVuln : 1);
    		System.out.println("Num criticas: "+entryData.getNumVulnerabilityCritical());	
    	}
    	
    	if (cmdLine.hasOption("vh")) {
    		Integer numVuln = Integer.parseInt(cmdLine.getOptionValue("vh"));  
    		entryData.setNumVulnerabilityHigh(numVuln != null ? numVuln : 1);
    		System.out.println("Num altas: "+entryData.getNumVulnerabilityHigh()); 		
    	}
    	
    	if (cmdLine.hasOption("vm")) {
    		Integer numVuln = Integer.parseInt(cmdLine.getOptionValue("vm"));  
    		entryData.setNumVulnerabilityMedium(numVuln != null ? numVuln : 5);
    		System.out.println("Num medias: "+entryData.getNumVulnerabilityMedium());
    	}
    	
    	if (cmdLine.hasOption("vl")) {
    		Integer numVuln = Integer.parseInt(cmdLine.getOptionValue("vl"));  
    		entryData.setNumVulnerabilityLow(numVuln != null ? numVuln : 10);
    		System.out.println("Num bajas: "+entryData.getNumVulnerabilityLow());
    	}
    	
    	if (cmdLine.hasOption("fa")) {
			String pathFileArachni = cmdLine.getOptionValue("fa");    		
    		Path path = Paths.get(pathFileArachni);
    		if(Files.exists(path)){
        		System.out.println("Se va a procesar el archivo: "+pathFileArachni);
    			entryData.setArachniResultData(Files.readAllBytes(path));
    		}
    	}
    	
    	if (cmdLine.hasOption("fz")) {
    		String pathFileZap = cmdLine.getOptionValue("fz");
    		Path path = Paths.get(pathFileZap);
    		if(Files.exists(path)){
	    		System.out.println("Se va a procesar el archivo: "+pathFileZap);
	    		entryData.setZapResultData(Files.readAllBytes(path));
    		}
    	}
    	
    	return entryData;
    	
    }
    
    /**
	 * Añade al mapa "groupVulnerabilities" todas las vulnerabilidades agrupadas 
	 * por el valor del tipo de vulnerabilidad configurado en el parametro "sisifoRelation".
	 * 
	 * También se eliminan las url por vulnerabilidad, que coincidan en url y metodo.
	 * 
	 * @param entryData datos de entrada de la aplicacion
	 * @param sisifoRelation mapa con la relación entre vulnerabilidades de las herramientas DAST y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    private static void getVulnerabilitiesArachni(EntryData entryData, SisifoRelation sisifoRelation, 
    		Map<String, Vulnerability> groupVulnerabilities) throws IOException, URISyntaxException {
    	
    	try {
            ArachniService arachniService = new ArachniService();
            arachniService.getVulnerabilities(entryData.getArachniResultData(), sisifoRelation.getArachni(), groupVulnerabilities);
        } catch (MalformedURLException e) {
            System.out.println("Fallo en la URL");
        }
    }
    
    /**
	 * Añade al mapa "groupVulnerabilities" todas las vulnerabilidades agrupadas 
	 * por el valor del tipo de vulnerabilidad configurado en el parametro "sisifoRelation".
	 * 
	 * También se eliminan las url por vulnerabilidad, que coincidan en url y metodo.
	 * 
	 * @param entryData datos de entrada de la aplicacion
	 * @param sisifoRelation mapa con la relación entre vulnerabilidades de las herramientas DAST y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    private static void getVulnerabilitiesZap(EntryData entryData, SisifoRelation sisifoRelation,
    		Map<String, Vulnerability> groupVulnerabilities) throws IOException, URISyntaxException {
    	
    	try {
            ZapService zapService = new ZapService();
            zapService.getVulnerabilities(entryData.getZapResultData(), sisifoRelation.getZap(), groupVulnerabilities);
        } catch (MalformedURLException e) {
            System.out.println("Fallo en la URL");
        }
    }

    /**
     * Valida si el objeto de entrada de datos esta vacio
     * 
     * @param entryData datos de entrada
     * @return 
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     */
    public static boolean checkNull(EntryData entryData) {
        for (Field f : EntryData.class.getDeclaredFields()){
        	f.setAccessible(true);
    		try {
    			if (f.get(entryData) != null)
    			    return false;
    		} catch (IllegalArgumentException | IllegalAccessException e) {
    			throw new RuntimeException(e.getMessage());
    		}
        }
        return true;
     }
    
}
