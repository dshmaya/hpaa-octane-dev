package com.hpe.application.automation.tools.ssc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by hijaziy on 7/23/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Projects extends SscBaseEntityArray<Projects.Project> {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Project {
        @JsonProperty("id")
        Integer id;
        @JsonProperty("name")
        String name;
    }
}