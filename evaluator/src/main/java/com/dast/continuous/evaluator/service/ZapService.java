package com.dast.continuous.evaluator.service;

import com.dast.continuous.evaluator.model.Vulnerability;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

public class ZapService {
    public Map<String, List<Vulnerability>> getVulnerabilities(String resource,
                                                               Map<String, String> zap,
                                                               Map<String, List<Vulnerability>> result)
            throws IOException, URISyntaxException {
        byte[] mapData = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(resource).toURI()));

        return result;
    }
}
