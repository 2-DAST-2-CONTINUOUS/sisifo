package com.dast.continuous.evaluator.main;

import com.dast.continuous.evaluator.model.EntryData;
import com.dast.continuous.evaluator.model.FinalReport;
import com.dast.continuous.evaluator.model.SisifoRelation;
import com.dast.continuous.evaluator.model.Vulnerability;
import com.dast.continuous.evaluator.service.ArachniService;
import com.dast.continuous.evaluator.service.EvaluatorLogicService;
import com.dast.continuous.evaluator.service.SisifoRelationService;
import com.dast.continuous.evaluator.service.ZapService;
import com.dast.continuous.evaluator.utils.ApplicationProperties;
import org.apache.commons.cli.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.Arrays;
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
        
        getVulnerabilitiesArachni(sisifoRelation, groupVulnerabilities);
        getVulnerabilitiesZap(sisifoRelation, groupVulnerabilities);

        List<Vulnerability> vulnerabilities = new ArrayList<>(groupVulnerabilities.values());
        
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
    	    	
    	if (cmdLine.hasOption("vc")) {
    		entryData.setNumVulnerabilityCritical(
    				Integer.parseInt(cmdLine.getOptionValue("vc")));    	
    	}
    	
    	if (cmdLine.hasOption("vh")) {
    		entryData.setNumVulnerabilityHigh(
    				Integer.parseInt(cmdLine.getOptionValue("vh")));    		
    	}
    	
    	if (cmdLine.hasOption("vm")) {
    		entryData.setNumVulnerabilityMedium(
    				Integer.parseInt(cmdLine.getOptionValue("vm")));     		
    	}
    	
    	if (cmdLine.hasOption("vl")) {
    		entryData.setNumVulnerabilityLow(
    				Integer.parseInt(cmdLine.getOptionValue("vl")));    		
    	}
    	
    	if (cmdLine.hasOption("fa")) {
			String pathFileArachni = cmdLine.getOptionValue("fa");				    	
			entryData.setArachniResultData(Files.readAllBytes(Paths.get(pathFileArachni)));			
    	}
    	
    	if (cmdLine.hasOption("fz")) {
    		String pathFileZap = cmdLine.getOptionValue("fz");
    		entryData.setZapResultData(Files.readAllBytes(Paths.get(pathFileZap)));
    	}
    	
    	return entryData;
    	
    }
    
    /**
	 * Añade al mapa "groupVulnerabilities" todas las vulnerabilidades agrupadas 
	 * por el valor del tipo de vulnerabilidad configurado en el parametro "sisifoRelation".
	 * 
	 * También se eliminan las url por vulnerabilidad, que coincidan en url y metodo.
	 *
	 * @param sisifoRelation mapa con la relación entre vulnerabilidades de las herramientas DAST y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    private static void getVulnerabilitiesArachni(SisifoRelation sisifoRelation, 
    		Map<String, Vulnerability> groupVulnerabilities) throws IOException, URISyntaxException {
    	String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.arachni.filepath");
    	try {
            ArachniService arachniService = new ArachniService();
            arachniService.getVulnerabilities(resource, sisifoRelation.getArachni(), groupVulnerabilities);
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
	 * @param sisifoRelation mapa con la relación entre vulnerabilidades de las herramientas DAST y 
	 * 		las vulnerabilidades configuradas en el evaluador
	 * @param groupVulnerabilities mapa con las vulnerabilidades agrupadas. Este puede 
	 * 		venir relleno de otras herramientas.
	 * @throws IOException
	 */
    private static void getVulnerabilitiesZap(SisifoRelation sisifoRelation,
    		Map<String, Vulnerability> groupVulnerabilities) throws IOException, URISyntaxException {
    	String resource = ApplicationProperties.INSTANCE.getAppName("dasttool.zap.filepath");
    	try {
            ZapService zapService = new ZapService();
            zapService.getVulnerabilities(resource, sisifoRelation.getZap(), groupVulnerabilities);
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
