/*
 * Certain versions of software and/or documents ("Material") accessible here may contain branding from
 * Hewlett-Packard Company (now HP Inc.) and Hewlett Packard Enterprise Company.  As of September 1, 2017,
 * the Material is now offered by Micro Focus, a separately owned and operated company.  Any reference to the HP
 * and Hewlett Packard Enterprise/HPE marks is historical in nature, and the HP and Hewlett Packard Enterprise/HPE
 * marks are the property of their respective owners.
 * __________________________________________________________________
 * MIT License
 *
 * (c) Copyright 2012-2019 Micro Focus or one of its affiliates.
 *
 * The only warranties for products and services of Micro Focus and its affiliates
 * and licensors ("Micro Focus") are set forth in the express warranty statements
 * accompanying such products and services. Nothing herein should be construed as
 * constituting an additional warranty. Micro Focus shall not be liable for technical
 * or editorial errors or omissions contained herein.
 * The information contained herein is subject to change without notice.
 * ___________________________________________________________________
 */

package com.microfocus.application.automation.tools.octane.actions;

import com.hp.octane.integrations.OctaneClient;
import com.hp.octane.integrations.OctaneSDK;
import com.hp.octane.integrations.dto.entities.Entity;
import com.hp.octane.integrations.dto.entities.EntityConstants;
import com.hp.octane.integrations.dto.entities.impl.EntityImpl;
import com.hp.octane.integrations.services.entities.EntitiesService;
import com.hp.octane.integrations.services.entities.QueryHelper;
import com.hp.octane.integrations.uft.items.UftTestDiscoveryResult;
import com.microfocus.application.automation.tools.model.OctaneServerSettingsModel;
import com.microfocus.application.automation.tools.octane.Messages;
import com.microfocus.application.automation.tools.octane.configuration.ConfigurationService;
import com.microfocus.application.automation.tools.octane.configuration.SDKBasedLoggerProvider;
import com.microfocus.application.automation.tools.octane.executor.*;
import com.microfocus.application.automation.tools.octane.executor.scmmanager.ScmPluginFactory;
import com.microfocus.application.automation.tools.octane.executor.scmmanager.ScmPluginHandler;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.Launcher;
import hudson.model.*;
import hudson.scm.NullSCM;
import hudson.scm.SCM;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.util.*;

/**
 * Post-build action of Uft test detection
 */

public class UFTTestDetectionPublisher extends Recorder {
    private static final Logger logger = SDKBasedLoggerProvider.getLogger(UFTTestDetectionPublisher.class);
    private String configurationId;
    private String workspaceName;
    private String scmRepositoryId;

    public String getWorkspaceName() {
        return workspaceName;
    }

    public String getScmRepositoryId() {
        return scmRepositoryId;
    }

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public UFTTestDetectionPublisher(String configurationId, String workspaceName, String scmRepositoryId) {
        this.configurationId = configurationId;
        this.workspaceName = workspaceName;
        this.scmRepositoryId = scmRepositoryId;
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
        UFTTestDetectionService.printToConsole(listener, "UFTTestDetectionPublisher is started.");

        //validate configuration id
        if (configurationId == null) {
            logger.error("discovery configurationId is null.");
            configurationId = tryFindConfigurationId(build, Long.parseLong(workspaceName));
            if (configurationId != null) {
                try {
                    build.getParent().save();
                } catch (IOException e) {
                    logger.error("Failed to save UFTTestDetectionPublisher : " + e.getMessage());
                }
            } else {
                logger.error("No relevant ALM Octane configuration is found.");
                build.setResult(Result.FAILURE);
                throw new IllegalArgumentException("No relevant ALM Octane configuration is found.");
            }
        }

        //validate scm repository id
        if (StringUtils.isEmpty(scmRepositoryId)) {
            String msg = "SCM repository field is empty. Get relevant scm repository id from ALM Octane SpaceConfiguration->DevOps->Scm Repositories. If you need to generate ScmRepository in ALM Octane based on your scm repository in job - set value \"-1\"";
            logger.error(msg);
            build.setResult(Result.FAILURE);
            throw new IllegalArgumentException(msg);
        }
        if (scmRepositoryId.equals("-1")) {
            try {
                generateScmRepository(build, listener);
            } catch (Exception e) {
                UFTTestDetectionService.printToConsole(listener, "Failed to generate Scm Repository in ALM Octane : " + e.getMessage());
                build.setResult(Result.FAILURE);
                return false;
            }
        }

        try {
            UftTestDiscoveryResult results = build.getWorkspace().act(new UFTTestDetectionCallable(build, configurationId, workspaceName, getScmRepositoryId(), listener));
            UFTTestDetectionBuildAction buildAction = new UFTTestDetectionBuildAction(build, results);
            build.addAction(buildAction);

            if (results.hasChanges()) {
                UFTTestDetectionService.publishDetectionResults(build, listener, results);
                UftTestDiscoveryDispatcher dispatcher = getExtension(UftTestDiscoveryDispatcher.class);
                dispatcher.enqueueResult(configurationId, build.getProject().getFullName(), build.getNumber(), workspaceName);

            }
            if (!results.getDeletedFolders().isEmpty()) {
                UFTTestDetectionService.printToConsole(listener, String.format("Found %s deleted folders", results.getDeletedFolders().size()));
                UFTTestDetectionService.printToConsole(listener, "To sync deleted items - full sync required. Triggering job with full sync parameter.");
                handleDeletedFolders(build);
            }
        } catch (Exception e) {
            UFTTestDetectionService.printToConsole(listener, "UFTTestDetectionPublisher.perform is failed : " + e.getMessage());
            build.setResult(Result.FAILURE);
        }

        return true;
    }

    private void generateScmRepository(AbstractBuild build, BuildListener listener) throws IOException {
        SCM scm = build.getProject().getScm();
        if (scm instanceof NullSCM) {
            throw new IllegalArgumentException("SCM definition is missing in the job");
        }
        ScmPluginHandler scmPluginHandler = ScmPluginFactory.getScmHandlerByScmPluginName(scm.getType());
        String url = ScmPluginFactory.getScmHandlerByScmPluginName(scm.getType()).getScmRepositoryUrl(scm);
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("SCM url is not defined in the job");
        }
        OctaneClient octaneClient = OctaneSDK.getClientByInstanceId(configurationId);
        EntitiesService entitiesService = octaneClient.getEntitiesService();


        List<String> conditions = Collections.singletonList(QueryHelper.condition(EntityConstants.Base.NAME_FIELD, url));
        long workspaceId = Long.parseLong(workspaceName);
        String collectionName = "scm_repositories";

        List<Entity> foundEntities = entitiesService.getEntities(workspaceId, collectionName, conditions, Collections.singletonList("id"));
        if (!foundEntities.isEmpty()) {
            scmRepositoryId = foundEntities.get(0).getId();
            UFTTestDetectionService.printToConsole(listener, "SCM repository " + url + " is already exist in ALM Octane with id=" + scmRepositoryId);
        } else {
            //create a new scm repository
            Entity newScmRepository = new EntityImpl();
            newScmRepository.setType("scm_repository");
            newScmRepository.setName(url);
            newScmRepository.setField("url", url);
            newScmRepository.setField("scm_type", scmPluginHandler.getScmType().getOctaneId());
            List<Entity> createEntities = entitiesService.postEntities(workspaceId, collectionName, Collections.singletonList(newScmRepository));
            scmRepositoryId = createEntities.get(0).getId();
            UFTTestDetectionService.printToConsole(listener, "SCM repository " + url + " is created in ALM Octane with id=" + scmRepositoryId);
        }

        build.getProject().save();
        UFTTestDetectionService.printToConsole(listener, "SCM repository field value is updated to " + scmRepositoryId);

    }

    private void handleDeletedFolders(AbstractBuild build) {
        //This situation is relevant for SVN only.
        //Deleting folder - SCM event doesn't supply information about deleted items in deleted folder - only top-level directory.
        //In this case need to do for each deleted folder - need to check with Octane what tests and data tables were under this folder.
        //so for each deleted folder - need to do at least 2 requests. In this situation - decided to activate full sync as it already tested scenario.
        //Full sync wil be triggered with delay of 60 secs to give the dispatcher possibility to sync other found changes

        //triggering full sync


        FreeStyleProject proj = (FreeStyleProject) build.getParent();
        List<ParameterValue> newParameters = new ArrayList<>();
        for (ParameterValue param : build.getAction(ParametersAction.class).getParameters()) {
            ParameterValue paramForSet;
            if (param.getName().equals(UftConstants.FULL_SCAN_PARAMETER_NAME)) {
                paramForSet = new BooleanParameterValue(UftConstants.FULL_SCAN_PARAMETER_NAME, true);
            } else {
                paramForSet = param;
            }
            newParameters.add(paramForSet);
        }

        ParametersAction parameters = new ParametersAction(newParameters);
        CauseAction causeAction = new CauseAction(new FullSyncRequiredCause(build.getId()));
        proj.scheduleBuild2(60, parameters, causeAction);

    }

    private static <T> T getExtension(Class<T> clazz) {
        ExtensionList<T> items = Jenkins.get().getExtensionList(clazz);
        return items.get(0);
    }

    private static String tryFindConfigurationId(AbstractBuild build, long workspaceId) {
        String result = null;
        List<OctaneClient> clients = OctaneSDK.getClients();
        logger.warn("number of configurations is " + clients.size());
        if (clients.size() == 1) {
            result = OctaneSDK.getClients().get(0).getInstanceId();
            logger.warn("selecting the only configurationId - " + result);
        } else if (clients.size() > 0) {
            String executorLogicalName = UftJobRecognizer.getExecutorLogicalName((FreeStyleProject) build.getParent());
            Collection<String> conditions = Collections.singletonList(QueryHelper.condition(EntityConstants.Base.LOGICAL_NAME_FIELD, executorLogicalName));
            for (OctaneClient client : clients) {
                try {
                    List<Entity> entities = client.getEntitiesService().getEntities(workspaceId, EntityConstants.Executors.COLLECTION_NAME, conditions, null);
                    if (!entities.isEmpty()) {
                        result = client.getInstanceId();
                        logger.warn("executor logical name found in configurationId - " + result);
                        break;
                    }
                } catch (Exception e) {
                    logger.warn("Failed to check executor logical name in configuration " + client.getInstanceId() + " : " + e.getMessage());
                }
            }
        }

        return result;
    }


    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    public String getConfigurationId() {
        return configurationId;
    }

    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        public ListBoxModel doFillConfigurationIdItems() {
            ListBoxModel m = new ListBoxModel();

            for (OctaneClient octaneClient : OctaneSDK.getClients()) {
                OctaneServerSettingsModel model = ConfigurationService.getSettings(octaneClient.getInstanceId());
                m.add(model.getCaption(), model.getIdentity());
            }
            return m;
        }

        public FormValidation doCheckConfigurationId(@QueryParameter String value) {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please select configuration");
            } else {
                return FormValidation.ok();
            }
        }

        public ListBoxModel doFillWorkspaceNameItems(@QueryParameter String configurationId, @QueryParameter(value = "workspaceName") String workspaceName) {
            ListBoxModel m = new ListBoxModel();
            if (StringUtils.isNotEmpty(configurationId)) {
                try {
                    EntitiesService entitiesService = OctaneSDK.getClientByInstanceId(configurationId).getEntitiesService();
                    List<Entity> workspaces = entitiesService.getEntities(null, "workspaces", null, null);
                    for (Entity workspace : workspaces) {
                        m.add(workspace.getName(), String.valueOf(workspace.getId()));
                    }
                } catch (Exception e) {
                    //octane configuration not found
                    m.add(workspaceName, workspaceName);
                    return m;
                }
            }
            return m;
        }

        public FormValidation doCheckWorkspaceName(@QueryParameter(value = "workspaceName") String value) {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please select workspace");
            }
            return FormValidation.ok();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return aClass.equals(FreeStyleProject.class);
        }

        public String getDisplayName() {
            return Messages.UFTTestDetectionPublisherConfigurationLabel();
        }
    }
}
