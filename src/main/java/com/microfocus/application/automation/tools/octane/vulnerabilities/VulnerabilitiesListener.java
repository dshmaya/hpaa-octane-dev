/*
 * © Copyright 2013 EntIT Software LLC
 *  Certain versions of software and/or documents (“Material”) accessible here may contain branding from
 *  Hewlett-Packard Company (now HP Inc.) and Hewlett Packard Enterprise Company.  As of September 1, 2017,
 *  the Material is now offered by Micro Focus, a separately owned and operated company.  Any reference to the HP
 *  and Hewlett Packard Enterprise/HPE marks is historical in nature, and the HP and Hewlett Packard Enterprise/HPE
 *  marks are the property of their respective owners.
 * __________________________________________________________________
 * MIT License
 *
 * © Copyright 2012-2018 Micro Focus or one of its affiliates.
 *
 * The only warranties for products and services of Micro Focus and its affiliates
 * and licensors (“Micro Focus”) are set forth in the express warranty statements
 * accompanying such products and services. Nothing herein should be construed as
 * constituting an additional warranty. Micro Focus shall not be liable for technical
 * or editorial errors or omissions contained herein.
 * The information contained herein is subject to change without notice.
 * ___________________________________________________________________
 *
 */

package com.microfocus.application.automation.tools.octane.vulnerabilities;

import com.hp.octane.integrations.OctaneSDK;
import com.hp.octane.integrations.api.VulnerabilitiesService;
import com.microfocus.application.automation.tools.octane.configuration.ConfigurationService;
import com.microfocus.application.automation.tools.octane.tests.build.BuildHandlerUtils;
import hudson.Extension;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.tasks.Publisher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.List;

/**
 * Jenkins events life cycle listener for processing vulnerabilities scan results on build completed
 */
@Extension
@SuppressWarnings({"squid:S2699", "squid:S3658", "squid:S2259", "squid:S1872"})
public class VulnerabilitiesListener {
	private static Logger logger = LogManager.getLogger(VulnerabilitiesListener.class);

	private static final String JENKINS_STORMRUNNER_LOAD_TEST_RUNNER_CLASS = "com.hpe.sr.plugins.jenkins.StormTestRunner";
	private static final String JENKINS_STORMRUNNER_FUNCTIONAL_TEST_RUNNER_CLASS = "com.hpe.application.automation.tools.srf.run.RunFromSrfBuilder";
	private static final String JENKINS_PERFORMANCE_CENTER_TEST_RUNNER_CLASS = "com.hpe.application.automation.tools.run.PcBuilder";

	VulnerabilitiesService vulnerabilitiesService = OctaneSDK.getInstance().getVulnerabilitiesService();



	public void processBuild(Run run) {
		String jobCiId = BuildHandlerUtils.getJobCiId(run);
		String buildCiId = BuildHandlerUtils.getBuildCiId(run);
//		if (!onFinalizedValidations(jobCiId, buildCiId)) {
//			logger.warn("Octane configuration is not valid");
//			return;
//		}
		final List<Publisher> publishers = ((AbstractBuild) run).getProject().getPublishersList().toList();
		for (Publisher publisher : publishers) {
			if ("com.fortify.plugin.jenkins.FPRPublisher".equals(publisher.getClass().getName())) {
				String projectName =  getFieldValueByReflection(publisher,"projectName");
				String projectVersion =  getFieldValueByReflection(publisher,"projectVersion");
				if(projectName!=null && projectVersion!=null){
					vulnerabilitiesService.enqueuePushVulnerabilitiesScanResult(jobCiId,buildCiId);
//					vulnerabilitiesService.enqueuePushVulnerabilitiesScanResult(jobCiId,String.valueOf(run.getNumber()-1));
//					vulnerabilitiesService.enqueuePushVulnerabilitiesScanResult(jobCiId,String.valueOf(run.getNumber()-2));
				}else{
					logger.warn("couldn't extract projectName\\projectVersion from FPRPublisher");
				}
			}
		}


	}


	private String getFieldValueByReflection(Object publisher,String fieldName) {
		Class<?> clazz = publisher.getClass();
		Field field = null; //Note, this can throw an exception if the field doesn't exist.
		try {
			field = clazz.getDeclaredField(fieldName);
			org.springframework.util.ReflectionUtils.makeAccessible(field);
			return field.get(publisher).toString();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (NoSuchFieldException e) {
			e.printStackTrace();
		}
		return null;
	}

	private boolean onFinalizedValidations(String jobCiId, String buildCiId){
		try {
			if (!(ConfigurationService.getServerConfiguration() != null && ConfigurationService.getServerConfiguration().isValid()) ||
					ConfigurationService.getModel().isSuspend()) {
				return false;
			}
			logger.info("enqueued build '" + jobCiId + " #" + buildCiId + "' for Security Scan submission");
			if (!OctaneSDK.getInstance().getVulnerabilitiesService().isVulnerabilitiesRelevant(jobCiId, buildCiId)){
				return false;
			}
		}catch (IOException e){
			logger.warn("failed on Finalized Validations ",e);
			return false;
		}

		return true;

	}
}
