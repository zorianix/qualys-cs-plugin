package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.Serializable;

import com.github.dockerjava.api.DockerClient;
import com.qualys.plugins.containerSecurity.util.DockerClientHelper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class TagImageSlaveCallable extends MasterToSlaveCallable<String, IOException> implements Serializable{
	private static final long serialVersionUID = -4143159957567745621L;
	private String image;
	private String imageId;
	private String dockerUrl;
	private String dockerCert;
	private TaskListener listener;
	
	public TagImageSlaveCallable(String image, String imageId, String dockerUrl, String dockerCert, TaskListener listener) {
		this.image = image;
		this.imageId = imageId;
		this.dockerUrl = dockerUrl;
		this.dockerCert = dockerCert;
		this.listener = listener;
	}
	
	public String call() throws IOException {
		DockerClientHelper helper = new DockerClientHelper(listener.getLogger());
		DockerClient dockerClient = helper.getDockerClient(dockerUrl, dockerCert);
		return helper.tagTheImage(dockerClient, image, imageId);
	}
}