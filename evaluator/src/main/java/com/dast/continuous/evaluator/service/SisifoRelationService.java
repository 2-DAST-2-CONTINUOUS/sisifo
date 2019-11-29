package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.SisifoRelation;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SisifoRelationService {

    /**
     * Recuperamos las relaciones parar ponderar las vulnerabilidades
     * @param relationResource
     * @return
     */
    public SisifoRelation getSisifoRelation(String relationResource) throws URISyntaxException, IOException {

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
