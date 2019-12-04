package com.qualys.plugins.containerSecurity.model;

import hudson.util.Secret;

public class ProxyConfiguration {

	private String proxyServer;
	private int proxyPort;
	private String proxyUsername;
	private Secret proxyPassword;
	private boolean useProxy;
	
	public ProxyConfiguration(boolean useProxy, String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
		this.useProxy = useProxy;
		this.proxyServer = proxyServer;
		this.proxyPort = proxyPort;
		this.proxyUsername = proxyUsername;
		this.proxyPassword = Secret.fromString(proxyPassword);
	}
	
	public boolean getUseProxy() {
		return useProxy;
	}
	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}
	public String getProxyServer() {
		return proxyServer;
	}
	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}
	public int getProxyPort() {
		return proxyPort;
	}
	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}
	public String getProxyUsername() {
		return proxyUsername;
	}
	public void setProxyUsername(String proxyUsername) {
		this.proxyUsername = proxyUsername;
	}
	public String getProxyPassword() {
		return proxyPassword.getPlainText();
	}
	public void setProxyPassword(String proxyPassword) {
		this.proxyPassword = Secret.fromString(proxyPassword);
	}
	
}
