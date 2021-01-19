package com.qualys.plugins.containerSecurity.util;

import java.io.PrintStream;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.DockerCmdExecFactory;
import com.github.dockerjava.api.command.InspectImageCmd;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.jaxrs.JerseyDockerCmdExecFactory;

import hudson.AbortException;

public class DockerClientHelper {
	private final static Logger logger = Logger.getLogger(Helper.class.getName());
	private PrintStream buildLogger;
	
	public DockerClientHelper() {
	}

	public DockerClientHelper(PrintStream buildLogger) {
		this.buildLogger = buildLogger;
	}
	
	public DockerClient getDockerClient(String dockerUrl, String dockerCert) {

    	if (dockerUrl == null || dockerUrl.isEmpty()) {
       		dockerUrl = "unix:///var/run/docker.sock";
       	}
    	//buildLogger.println("Using docker daemon URL : " + dockerUrl );
    	DockerClientConfig config = null;
		if(StringUtils.isEmpty(dockerCert)) {
			config = DefaultDockerClientConfig.createDefaultConfigBuilder()
					  .withDockerHost(dockerUrl)
					  .withDockerTlsVerify(false)
					  .build();
		}else {
			//buildLogger.println("Using docker cert path : " + dockerCert);
			config = DefaultDockerClientConfig.createDefaultConfigBuilder()
					  .withDockerHost(dockerUrl)
					  .withDockerTlsVerify(true)
					  .withDockerCertPath(dockerCert)
					  .build();
		}

		// using jaxrs/jersey implementation here (netty impl is also available)
		DockerCmdExecFactory dockerCmdExecFactory = new JerseyDockerCmdExecFactory()
		  .withReadTimeout(10000)
		  .withConnectTimeout(10000)
		  .withMaxTotalConnections(1000)
		  .withMaxPerRouteConnections(100);

		DockerClient dockerClient = DockerClientBuilder.getInstance(config)
		  .withDockerCmdExecFactory(dockerCmdExecFactory)
				  .build();
		return dockerClient;
			
     }
	    
	public String fetchImageId(DockerClient dockerClient, String image) throws AbortException, UnknownHostException {
		try {
		InspectImageCmd inspect = dockerClient.inspectImageCmd(image);
		String imageIdSha256 = inspect.exec().getId();
		//buildLogger.println("#### Image sha256 for "+ image +" is = " + imageIdSha256);
		
		String imageIds[] = imageIdSha256.split(":");  //split by :
		String first12char = imageIds[1].substring(0,12);
		buildLogger.println("Image Id extracted for " + image + " = "+ first12char);
		return first12char;
		
		}catch (Exception e) {
			buildLogger.println("Failed to extract image Id associated with '" + image + "' ; Reason : " + e.getMessage());
			throw new AbortException("Failed to extract image Id associated with '" + image + "'.");
		}
	}
	
	  public String tagTheImage(DockerClient dockerClient, String imageIdOrName, String imageId) throws AbortException {
		  
		  if (imageId != null ) {
			  try {
				String taggingTime = Long.toString(System.currentTimeMillis());
				dockerClient.tagImageCmd(imageIdOrName, "qualys_scan_target", imageId).withForce(true).exec();
				buildLogger.println("Tagged image(" + imageIdOrName + ") successfully at timestamp " + taggingTime);
				return taggingTime;
			  } catch(Exception e) {
	    		for (StackTraceElement traceElement : e.getStackTrace())
	                logger.info("\tat " + traceElement);
	    		buildLogger.println("Failed to tag the image " + imageIdOrName + " with qualys_scan_target.. Reason : " + e.getMessage());
	    		throw new AbortException("Failed to tag the image " + imageIdOrName + " with qualys_scan_target.. Reason : " + e.getMessage());
			  }
	    }
		  return null;
	}
	  
	  public boolean isCICDSensorUp(DockerClient dockerClient) throws AbortException {
		  List<Container> containers = dockerClient.listContainersCmd().exec();
		  for (Container container: containers) {
			  Map<String, String> labels = container.getLabels();
			  if (labels.get("VersionInfo") != null && labels.get("VersionInfo").contains("Qualys Sensor")) {
				  return container.getCommand()!=null && container.getCommand().contains("cicd-deployed-sensor") ? true : false;
			  }
		  }
		  throw new AbortException("Qualys CS sensor container is not running... Please check if sensor is configured correctly.");
	  }
	  
}
