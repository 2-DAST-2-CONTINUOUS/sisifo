package com.dast.continuous.evaluator.utils;

import java.io.IOException;
import java.util.Properties;

public enum ApplicationProperties {
    INSTANCE;

    private final Properties properties;

    ApplicationProperties() {
        properties = new Properties();
        try {
            properties.load(getClass().getClassLoader().getResourceAsStream("application.properties"));
        } catch (IOException e) {
           System.out.println("Error leyendo Properties");
        }
    }

    public String getAppName(String property) {
        return properties.getProperty(property);
    }
}
