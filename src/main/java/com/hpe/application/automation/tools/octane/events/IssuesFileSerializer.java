package com.hpe.application.automation.tools.octane.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hp.octane.integrations.dto.SecurityScans.OctaneIssue;
import hudson.model.Run;

import java.io.File;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IssuesFileSerializer {
    Run run;
    List<OctaneIssue> octaneIssues;
    public IssuesFileSerializer(Run r, List<OctaneIssue> issues){
        this.run = r;
        this.octaneIssues = issues;
    }

    public void doSerialize() {
        try{
            Map dataFormat = new HashMap<>();
            dataFormat.put("data",octaneIssues);
            String vulnerabilitiesScanFilePath = run.getLogFile().getParent() + File.separator + SSCHandler.SCAN_RESULT_FILE;
            PrintWriter fw = new PrintWriter(vulnerabilitiesScanFilePath, "UTF-8");
            new ObjectMapper().writeValue(fw,dataFormat);
            fw.flush();
            fw.close();
        }catch(Exception e){
            System.out.println(e);
        }

    }
}
