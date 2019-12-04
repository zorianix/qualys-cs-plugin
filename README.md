# Qualys Container Security Plugin

## About

The Qualys Container Security Plugin for Jenkins empowers DevOps to assess docker images in their existing CI/CD processes with help of Qualys Container Security module. Integrating this assessment step will help you catch and eliminate docker images related flaws. This plugin supports pipeline as well as free-style projects.

## How this plugin works
Jenkins CS plugin automatically tags images built out of CI/CD pipeline with the tag qualys_scan_target:<image-id> to mark them for scanning by qualys sensor and only those images are scanned for vulnerabilities. Once the scanning is over, Qualys Container Sensor will remove the tag. However, if an image has no other tag applied to it other than 'qualys_scan_target:<image-id>', the sensor will retain the tag to avoid removal of the image from the host.
The sensor uploads all the data for configured image to the Qualys platform. Qualys container Security module quickly analyzes it and responds with vulnerabilities. If you have configured any pass/fail criteria, the plugin evaluates the response against that. If it finds something is not matching your criteria, it will cause exception to fail your build. Otherwise, your build job proceeds to next step (if any). 

## How to use this plugin

### Prerequisites

* A valid Qualys subscription with the Container Security application activated
* Access to Qualys Container Security application API endpoint from your build host.
* Requires the container sensor for CI/CD environment to be installed on the jenkins build host. Refer to Qualys Container Security Sensor Deployment Guide for instructions on installing the container cicd sensor. You must pass the following parameter while deploying the sensor for CI/CD environment --cicd-deployed-sensor or -c.
* Internet connection for slave to be able to connect to the Qualys Cloud Platform. Install sensor with proxy option if slave is running behind proxy. 
* The Jenkins master and slave nodes should have an open connection to the Qualys Cloud Platform in order to get data from the Qualys Cloud Platform for vulnerability reporting.

### Where to use this plugin step

We recommend using this plugin step during "Post-build" phase of your job, right after you build a docker image. 

### Configuration

If you are using pipeline, you should go to "Pipeline Syntax", and select `getImageVulnsFromQualys` step.
If you are using freestyle, you should add `Get Docker image vulnerabilities from Qualys` build step.

A form appears with several input fields. Now you are ready to configure the plugin. 

#### Qualys Credentials

1. Enter your Qualys API server URL. 
2. Select/Add your Qualys API Credentials.
3. If you need proxy to communicate to the Internet, set correct proxy settings. 
4. To confirm that Jenkins can communicate to Qualys Cloud Platform and APIs, use `Test Connection` button.

#### Image Id/ Image name

The field image IDs/Image Names is used to set the docker image Ids or names you want to report on. The plugin will only pull a report for the image Ids/names you specify. It is a comma separated list. You can also provide image ids through an environment variable.  

#### Pass/Fail Criteria

You can optionally fail the build based on vulnerabilities. 

1. Configure to fail a build if the number of detections exceeds the limit specified for one or more severity types. For example, to fail a build if severity 5 vulnerabilities count is more than 2, select the “Fail with more than severity 5” option and specify 2.
2. Configure to fail a build if the configured QIDs found in the scan result.
3. Configure to fail a build if the configured CVEs found in the scan result.
4. Configure to fail a build if configured softwares names are found in scan result.
5. Configure to fail build by CVSS Base score - This can be either using CVSS v2 or CVSS v3.

By default the pass/fail criteria is applied to Confirmed type of vulnerabilities. We can apply above fail conditions to potential vulnerabilities as well by configuring its checkbox.

You can also exclude some conditions - You can configure a comma separated list of either CVEs or QIDs to exclude from the build failure conditions.

### Generate Pipeline Script *(for pipeline project only)*

If you are configuring pipeline project, click the `Generate Pipeline Script` button. It will give you a command which you can copy and paste in your project's pipeline script. 
