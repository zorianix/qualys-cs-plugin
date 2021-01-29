package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.Serializable;

import com.github.dockerjava.api.DockerClient;
import com.qualys.plugins.containerSecurity.util.DockerClientHelper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class CheckSensorSlaveCallable extends MasterToSlaveCallable<Boolean, IOException> implements Serializable{
	
	private static final long serialVersionUID = 1L;
	private String dockerUrl;
	private String dockerCert;
	private TaskListener listener;
	
	public CheckSensorSlaveCallable(String dockerUrl, String dockerCert, TaskListener listener) {
		
		this.dockerUrl = dockerUrl;
		this.dockerCert = dockerCert;
		this.listener = listener;
	}
	
	public Boolean call() throws IOException {
		DockerClientHelper helper = new DockerClientHelper(listener.getLogger());
		DockerClient dockerClient = helper.getDockerClient(dockerUrl, dockerCert);
		return helper.isCICDSensorUp(dockerClient);
	}
}

