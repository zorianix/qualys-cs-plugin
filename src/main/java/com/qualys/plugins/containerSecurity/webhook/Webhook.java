package com.qualys.plugins.containerSecurity.webhook;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.lang.StringUtils;

import com.qualys.plugins.containerSecurity.model.ProxyConfiguration;

import jenkins.model.Jenkins;

public class Webhook{
	
	private PrintStream buildLogger;
	private final String url;
    private final String data;
    private final ProxyConfiguration proxy;
    
    private static final int timeout = 60;
    private static final int RETRIES = 1;
    private final static Logger logger = Logger.getLogger(Webhook.class.getName());

    public Webhook(String url, String data, PrintStream logger, ProxyConfiguration proxy) {
        this.url = url;
        this.data = data;
        this.buildLogger = logger;
        this.proxy = proxy;
    }
    
    private HttpClient getHttpClient() {
        HttpClient client = new HttpClient();
        Jenkins jen = Jenkins.getInstance();
        if (jen != null) {
            if (proxy.getUseProxy()) {
                client.getHostConfiguration().setProxy(proxy.getProxyServer(), proxy.getProxyPort());
                String username = proxy.getProxyUsername();
                String password = proxy.getProxyPassword();
                // Consider it to be passed if username specified.
                if (StringUtils.isNotBlank(username)) {
                    client.getState().setProxyCredentials(AuthScope.ANY,
                            new UsernamePasswordCredentials(username, password));
                }
            }
        }
        return client;
    }
    
    public void post() {
        int tried = 0;
        boolean success = false;
        HttpClient client = getHttpClient();
        client.getParams().setConnectionManagerTimeout(timeout);
        buildLogger.println("Sending scanned result data to webhook URL - " + url);
        logger.info("Sending scanned result data to webhook URL - " + url);
        do {
            tried++;
            RequestEntity requestEntity;
            try {
                // uncomment to log what message has been sent
                logger.info("Posted JSON: " + data);
                requestEntity = new StringRequestEntity(data, "application/json", StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace(buildLogger);
                break;
            }

            PostMethod post = new PostMethod(url);
            try {
                post.setRequestEntity(requestEntity);
                int responseCode = client.executeMethod(post);
                if (responseCode != HttpStatus.SC_OK) {
                    String response = post.getResponseBodyAsString();
                    buildLogger.println("Posting data to " + url + " may have failed. Webhook responded with status code - " + responseCode);
                    logger.info("Posting data to " + url + " may have failed. Webhook responded with status code - " + responseCode);
                    logger.info("Message from webhook - "+ response);

                } else {
                    success = true;
                }
            } catch (IOException e) {
            	buildLogger.println("Failed to post data to webhook URL - " + url);
            	logger.info("Failed to post data to webhook URL - " + url);
                e.printStackTrace(buildLogger);
            } finally {
                post.releaseConnection();
            }
        } while (tried < RETRIES && !success);
        if(success) {
        	buildLogger.println("Successfully posted data to webhook URL - " + url);
        	logger.info("Successfully posted data to webhook URL - " + url);
        }

    }
	
}