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

package com.microfocus.application.automation.tools.octane.configuration;

import com.hp.octane.integrations.OctaneSDK;
import com.hp.octane.integrations.dto.entities.Entity;
import com.hp.octane.integrations.exceptions.OctaneConnectivityException;
import com.hp.octane.integrations.exceptions.OctaneSDKGeneralException;
import com.hp.octane.integrations.utils.OctaneUrlParser;
import com.microfocus.application.automation.tools.model.OctaneServerSettingsModel;
import com.microfocus.application.automation.tools.octane.CIJenkinsServicesImpl;
import com.microfocus.application.automation.tools.octane.ImpersonationUtil;
import com.microfocus.application.automation.tools.octane.Messages;
import com.microfocus.application.automation.tools.octane.exceptions.AggregatedMessagesException;
import hudson.ProxyConfiguration;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import hudson.security.ACLContext;
import hudson.security.Permission;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class ConfigurationValidator {
    private final static Logger logger = SDKBasedLoggerProvider.getLogger(ConfigurationValidator.class);


    private ConfigurationValidator() {
        //hiding public constructor
    }


    public static OctaneUrlParser parseUiLocation(String uiLocation) throws FormValidation {
        try {
            return OctaneUrlParser.parse(uiLocation);
        } catch (OctaneSDKGeneralException e) {
            throw wrapWithFormValidation(false, e.getMessage());
        }
    }

    /**
     * Used by tests only
     *
     * @param location
     * @param sharedSpace
     * @param username
     * @param password
     * @return
     */
    public static FormValidation checkConfigurationAndWrapWithFormValidation(String location, String sharedSpace, String username, Secret password) {
        List<String> errors = new ArrayList<>();
        checkConfiguration(errors, location, sharedSpace, username, password);
        return wrapWithFormValidation(errors.isEmpty(), errors.isEmpty() ? Messages.ConnectionSuccess() : errors.get(0));
    }

    public static List<Entity> checkConfiguration(List<String> errorMessages, String location, String sharedSpace, String username, Secret password) {

        try {
            return OctaneSDK.testOctaneConfigurationAndFetchAvailableWorkspaces(location, sharedSpace, username, password.getPlainText(), CIJenkinsServicesImpl.class);
        } catch (OctaneConnectivityException octaneException) {
            errorMessages.add(octaneException.getErrorMessageVal());
        } catch (IOException ioe) {
            logger.warn("Connection check failed due to communication problem", ioe);
            errorMessages.add(Messages.ConnectionFailure());
        }
        return Collections.emptyList();
    }

    public static void checkImpersonatedUser(List<String> errorMessages, String impersonatedUser) {
        User jenkinsUser = null;
        if (!StringUtils.isEmpty(impersonatedUser)) {
            jenkinsUser = User.get(impersonatedUser, false, Collections.emptyMap());
            if (jenkinsUser == null) {
                errorMessages.add(String.format(Messages.JenkinsUserMisconfiguredFailure(), impersonatedUser));
                return;
            }
        }

        ACLContext impersonatedContext = null;
        try {
            //start impersonation
            impersonatedContext = ImpersonationUtil.startImpersonation(jenkinsUser);

            //test permissions
            Map<Permission, String> requiredPermissions = new HashMap<>();
            requiredPermissions.put(Item.BUILD, "Job.BUILD");
            requiredPermissions.put(Item.READ, "Job.READ");
            Jenkins jenkins = Jenkins.get();
            Set<String> missingPermissions = requiredPermissions.keySet().stream().filter(p -> !jenkins.hasPermission(p)).map(p -> requiredPermissions.get(p)).collect(Collectors.toSet());
            if (!missingPermissions.isEmpty()) {
                errorMessages.add(String.format(Messages.JenkinsUserPermissionsFailure(), impersonatedUser, StringUtils.join(missingPermissions, ", ")));
            }
        } catch (Exception e) {
            errorMessages.add(String.format(Messages.JenkinsUserUnexpectedError(), impersonatedUser, e.getMessage()));
        } finally {
            //depersonate
            ImpersonationUtil.stopImpersonation(impersonatedContext);
        }
    }

    private static Set<String> getAvailableJobNames(List<String> errorMessages, String impersonatedUser) {
        User jenkinsUser = User.get(impersonatedUser, false, Collections.emptyMap());
        if (jenkinsUser == null) {
            errorMessages.add(String.format(Messages.JenkinsUserMisconfiguredFailure(), impersonatedUser));
            return Collections.emptySet();
        }

        ACLContext impersonatedContext = null;
        try {
            //start impersonation
            impersonatedContext = ImpersonationUtil.startImpersonation(jenkinsUser);

            //get job names
            Collection<String> jobNames = Jenkins.get().getJobNames();
            Set<String> validJobNames = jobNames.stream().filter(jobName -> CIJenkinsServicesImpl.isJobIsRelevantForPipelineModule((Job) Jenkins.get().getItemByFullName(jobName)))
                    .collect(Collectors.toSet());
            return validJobNames;
        } catch (Exception e) {
            errorMessages.add(String.format(Messages.JenkinsUserUnexpectedError(), impersonatedUser, e.getMessage()));
            return Collections.emptySet();
        } finally {
            //depersonate
            ImpersonationUtil.stopImpersonation(impersonatedContext);
        }
    }

    public static FormValidation wrapWithFormValidation(boolean success, String message) {
        String color = success ? "green" : "red";
        String msg = "<font color=\"" + color + "\" >" + message + "</font>";
        if (success) {
            return FormValidation.okWithMarkup(msg);
        } else {
            return FormValidation.errorWithMarkup(msg);
        }
    }

    public static void checkHoProxySettins(List<String> errorMessages) {
        ProxyConfiguration proxy = Jenkins.get().proxy;
        boolean containsHttp = (proxy != null && proxy.getNoProxyHostPatterns().stream().anyMatch(p -> p.pattern().toLowerCase().startsWith("http")));
        if (containsHttp) {
            errorMessages.add("In the HTTP Proxy Configuration area, the No Proxy Host field must contain a host name only. Remove the http:// prefix before the host name.");
        }
    }

    public static Map<Long, String> checkWorkspace2ImpersonatedUserConf(String workspace2ImpersonatedUserConf, List<Entity> availableWorkspaces, String impersonatedUser, List<String> errorMessages) {
        Map<Long, String> workspace2ImpersonatedUser = Collections.emptyMap();
        if (workspace2ImpersonatedUserConf == null || workspace2ImpersonatedUserConf.trim().isEmpty()) {
            return workspace2ImpersonatedUser;
        }

        //collect parse errors
        try {
            OctaneServerSettingsModel.parseWorkspace2ImpersonatedUserConf(workspace2ImpersonatedUserConf, false);
        } catch (AggregatedMessagesException e) {
            errorMessages.addAll(e.getMessages());
        }

        if (!availableWorkspaces.isEmpty()) {
            workspace2ImpersonatedUser = OctaneServerSettingsModel.parseWorkspace2ImpersonatedUserConf(workspace2ImpersonatedUserConf, true);

            //try to find  non-accessible workspaces
            Set<Long> accessibleWorkspaceIds = availableWorkspaces.stream().map(Entity::getId).map(id -> Long.parseLong(id)).collect(Collectors.toSet());
            List<Long> notAccessibleWorkspaceIds = workspace2ImpersonatedUser.keySet().stream().filter(workspaceId -> !accessibleWorkspaceIds.contains(workspaceId)).collect(Collectors.toList());
            if (!notAccessibleWorkspaceIds.isEmpty()) {
                errorMessages.add("Workspace configuration contains non-accessible ALM Octane workspaces: " + notAccessibleWorkspaceIds);
            }

            List<String> tempErrorListForGeneralImpersonatedUser = new ArrayList<>();

            //get available jobs for general jenkins user for comparison with jobs of workspace jenkins user
            Set<String> availableJobsForGeneralJenkinsUser = getAvailableJobNames(tempErrorListForGeneralImpersonatedUser, impersonatedUser);

            //validate that workspace impersonated uses has access to subset of jobs available to general impersonated user
            Set<String> userNames = workspace2ImpersonatedUser.values().stream().collect(Collectors.toSet());
            userNames.forEach(user -> {
                Set<String> availableJobs = getAvailableJobNames(errorMessages, user);
                if (availableJobs.isEmpty()) {
                    errorMessages.add(String.format("No job is available to the workspace Jenkins user '%s'", user));
                } else {
                    Set<String> unavailableJobsByGeneralImpersonatedUser = availableJobs.stream()
                            .filter(jobName -> !availableJobsForGeneralJenkinsUser.contains(jobName)).collect(Collectors.toSet());
                    if (!unavailableJobsByGeneralImpersonatedUser.isEmpty()) {
                        errorMessages.add(String.format("There are jobs that are not accessible by '%s', but are accessible by the workspace jenkins user '%s', for example %s ",
                                impersonatedUser, user,
                                unavailableJobsByGeneralImpersonatedUser.stream().limit(3).collect(Collectors.toSet())));
                    }
                }
            });
        }
        return workspace2ImpersonatedUser;
    }
}
