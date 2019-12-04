package com.qualys.plugins.containerSecurity.model;

import hudson.util.Secret;

public class QualysServerCreds {

	private String serverURL;
	private String username;
	private Secret password;
	
	public QualysServerCreds(String serverURL, String username, String password) {
		serverURL = serverURL.replaceAll("/$", "");
		this.serverURL = serverURL;
		this.username = username;
		this.password = Secret.fromString(password);
	}
	
	public String getServerURL() {
		return serverURL;
	}
	public void setServerURL(String serverURL) {
		this.serverURL = serverURL;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password.getPlainText();
	}
	public void setPassword(String password) {
		this.password = Secret.fromString(password);
	}
}
