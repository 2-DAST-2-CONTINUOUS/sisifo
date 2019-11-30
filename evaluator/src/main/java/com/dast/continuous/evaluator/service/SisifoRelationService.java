package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.SisifoRelation;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

public class SisifoRelationService {

    /**
     * Recuperamos las relaciones parar ponderar las vulnerabilidades
     * @param relationResource
     * @return
     */
    public SisifoRelation getSisifoRelation(String relationResource) throws IOException {
    	
    	InputStream in = ClassLoader.getSystemResourceAsStream(relationResource);
    	
        ///converting json to Map
        byte[] mapData = IOUtils.toByteArray(in);

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
