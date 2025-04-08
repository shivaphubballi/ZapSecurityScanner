package com.securitytesting.zap.scanner;

import com.securitytesting.zap.auth.AuthenticationHandler;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.ScanPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;
import java.util.Map;

import java.util.Map;

import java.util.concurrent.TimeUnit;

/**
 * Scanner for web applications.
 * Supports standard, passive, and active scanning with authentication.
 */
public class WebAppScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebAppScanner.class);
    private static final long POLL_INTERVAL_MS = 2000;

    private final ClientApi zapClient;

    /**
     * Creates a WebAppScanner with the specified ZAP client.
     * 
     * @param zapClient ZAP Client API instance
     */
    public WebAppScanner(ClientApi zapClient) {
        this.zapClient = zapClient;
    }

    /**
     * Performs a security scan on a web application.
     * 
     * @param config The scan configuration
     * @throws ZapScannerException if the scan fails
     */
    public void scan(ScanConfig config) throws ZapScannerException {
        LOGGER.info("Starting web application security scan for: {}", config.getTargetUrl());
        
        try {
            // Create a new context
            int contextId = createContext(config);
            LOGGER.debug("Created context with ID: {}", contextId);
            
            // Configure authentication if needed
            if (config.requiresAuthentication()) {
                AuthenticationHandler authHandler = config.getAuthenticationHandler();
                authHandler.configureAuthentication(zapClient, config.getAuthenticationConfig(), contextId);
                authHandler.createAuthentication(zapClient, config.getAuthenticationConfig(), contextId);
                
                if (!authHandler.verifyAuthentication(zapClient, config.getAuthenticationConfig(), contextId)) {
                    throw new ZapScannerException("Authentication verification failed");
                }
            }
            
            // Configure and apply scan policy if specified
            if (config.getScanPolicy() != null) {
                applyScanPolicy(config.getScanPolicy());
            }
            
            // Spider the target
            if (config.isSpiderEnabled()) {
                spiderTarget(config, contextId);
            }
            
            // AJAX Spider if needed
            if (config.isAjaxSpiderEnabled()) {
                ajaxSpiderTarget(config, contextId);
            }
            
            // Passive scan happens automatically as requests are made
            if (config.isPassiveScanEnabled()) {
                waitForPassiveScan();
            }
            
            // Active scan if enabled
            if (config.isActiveScanEnabled()) {
                activeScanTarget(config, contextId);
            }
            
            // Cleanup authentication resources
            if (config.requiresAuthentication()) {
                AuthenticationHandler authHandler = config.getAuthenticationHandler();
                authHandler.cleanup(zapClient, contextId);
            }
            
            LOGGER.info("Web application security scan completed for: {}", config.getTargetUrl());
            
        } catch (Exception e) {
            LOGGER.error("Failed to perform web application scan", e);
            throw new ZapScannerException("Failed to perform web application scan", e);
        }
    }

    private int createContext(ScanConfig config) throws ClientApiException {
        LOGGER.debug("Creating a new context for target: {}", config.getTargetUrl());
        
        // Create a new context
        String contextName = "context-" + System.currentTimeMillis();
        ApiResponse response = zapClient.context.newContext(contextName);
        String contextId = ((ApiResponseElement) response).getValue();
        
        // Add target URL to context
        zapClient.context.includeInContext(contextName, config.getTargetUrl() + ".*");
        
        // Add any additional include paths
        for (String includePath : config.getIncludePaths()) {
            zapClient.context.includeInContext(contextName, includePath);
        }
        
        // Add any exclude paths
        for (String excludePath : config.getExcludePaths()) {
            zapClient.context.excludeFromContext(contextName, excludePath);
        }
        
        return Integer.parseInt(contextId);
    }

    private void applyScanPolicy(ScanPolicy policy) throws ClientApiException {
        LOGGER.debug("Applying scan policy: {}", policy.getName());
        
        // Apply scan policy
        String policyName = policy.getName();
        
        // Check if policy exists, create if not
        try {
            zapClient.ascan.addScanPolicy(policyName);
        } catch (ClientApiException e) {
            // Policy might already exist
            LOGGER.debug("Policy may already exist: {}", e.getMessage());
        }
        
        // Configure policy based on enabled/disabled scanners
        for (int scannerId : policy.getEnabledScanners()) {
            zapClient.ascan.enableScanners(String.valueOf(scannerId), policyName);
        }
        
        for (int scannerId : policy.getDisabledScanners()) {
            zapClient.ascan.disableScanners(String.valueOf(scannerId), policyName);
        }
        
        // Configure policy parameters
        for (Map.Entry<String, String> entry : policy.getParameters().entrySet()) {
            zapClient.ascan.setScannerAttackStrength(
                    entry.getKey(), 
                    entry.getValue(), 
                    policyName);
        }
    }

    private void spiderTarget(ScanConfig config, int contextId) throws ClientApiException, InterruptedException {
        LOGGER.debug("Starting spider for target: {}", config.getTargetUrl());
        
        ApiResponse response;
        if (config.requiresAuthentication()) {
            // Get the user ID for authenticated scanning
            ApiResponse usersResponse = zapClient.users.usersList(contextId);
            String userId = usersResponse.toString().replaceAll(".*userId=([^\\s]+).*", "$1");
            
            // Spider as user
            response = zapClient.spider.scanAsUser(
                    config.getTargetUrl(), 
                    contextId, 
                    userId);
        } else {
            // Spider without authentication
            response = zapClient.spider.scan(config.getTargetUrl());
        }
        
        String scanId = ((ApiResponseElement) response).getValue();
        LOGGER.debug("Spider scan started with ID: {}", scanId);
        
        // Wait for spider to complete
        int progress;
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.MINUTES.toMillis(config.getTimeoutInMinutes());
        
        do {
            Thread.sleep(POLL_INTERVAL_MS);
            progress = Integer.parseInt(((ApiResponseElement) zapClient.spider.status(scanId)).getValue());
            LOGGER.debug("Spider progress: {}%", progress);
            
            if (System.currentTimeMillis() - startTime > timeout) {
                LOGGER.warn("Spider timed out, stopping");
                zapClient.spider.stop(scanId);
                break;
            }
        } while (progress < 100);
        
        LOGGER.debug("Spider completed");
    }

    private void ajaxSpiderTarget(ScanConfig config, int contextId) throws ClientApiException, InterruptedException {
        LOGGER.debug("Starting AJAX spider for target: {}", config.getTargetUrl());
        
        if (config.requiresAuthentication()) {
            // Get the user ID for authenticated scanning
            ApiResponse usersResponse = zapClient.users.usersList(contextId);
            String userId = usersResponse.toString().replaceAll(".*userId=([^\\s]+).*", "$1");
            
            // AJAX Spider as user
            zapClient.ajaxSpider.scanAsUser(
                    config.getTargetUrl(), 
                    contextId, 
                    userId);
        } else {
            // AJAX Spider without authentication
            zapClient.ajaxSpider.scan(config.getTargetUrl());
        }
        
        LOGGER.debug("AJAX Spider started");
        
        // Wait for AJAX Spider to complete
        String status;
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.MINUTES.toMillis(config.getTimeoutInMinutes());
        
        do {
            Thread.sleep(POLL_INTERVAL_MS);
            status = ((ApiResponseElement) zapClient.ajaxSpider.status()).getValue();
            LOGGER.debug("AJAX Spider status: {}", status);
            
            if (System.currentTimeMillis() - startTime > timeout) {
                LOGGER.warn("AJAX Spider timed out, stopping");
                zapClient.ajaxSpider.stop();
                break;
            }
        } while (!status.equals("stopped"));
        
        LOGGER.debug("AJAX Spider completed");
    }

    private void waitForPassiveScan() throws ClientApiException, InterruptedException {
        LOGGER.debug("Waiting for passive scan to complete");
        
        // Wait for passive scan to complete
        int recordsToScan;
        do {
            Thread.sleep(POLL_INTERVAL_MS);
            ApiResponse response = zapClient.pscan.recordsToScan();
            recordsToScan = Integer.parseInt(((ApiResponseElement) response).getValue());
            LOGGER.debug("Passive scan records to scan: {}", recordsToScan);
        } while (recordsToScan > 0);
        
        LOGGER.debug("Passive scan completed");
    }

    private void activeScanTarget(ScanConfig config, int contextId) throws ClientApiException, InterruptedException {
        LOGGER.debug("Starting active scan for target: {}", config.getTargetUrl());
        
        ApiResponse response;
        if (config.requiresAuthentication()) {
            // Get the user ID for authenticated scanning
            ApiResponse usersResponse = zapClient.users.usersList(contextId);
            String userId = usersResponse.toString().replaceAll(".*userId=([^\\s]+).*", "$1");
            
            // Active scan as user
            response = zapClient.ascan.scanAsUser(
                    config.getTargetUrl(), 
                    contextId, 
                    userId, 
                    config.getScanPolicy() != null ? config.getScanPolicy().getName() : null);
        } else {
            // Active scan without authentication
            response = zapClient.ascan.scan(
                    config.getTargetUrl(), 
                    "true", 
                    "true", 
                    config.getScanPolicy() != null ? config.getScanPolicy().getName() : null, 
                    null, 
                    null);
        }
        
        String scanId = ((ApiResponseElement) response).getValue();
        LOGGER.debug("Active scan started with ID: {}", scanId);
        
        // Wait for active scan to complete
        int progress;
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.MINUTES.toMillis(config.getTimeoutInMinutes());
        
        do {
            Thread.sleep(POLL_INTERVAL_MS);
            progress = Integer.parseInt(((ApiResponseElement) zapClient.ascan.status(scanId)).getValue());
            LOGGER.debug("Active scan progress: {}%", progress);
            
            if (System.currentTimeMillis() - startTime > timeout) {
                LOGGER.warn("Active scan timed out, stopping");
                zapClient.ascan.stop(scanId);
                break;
            }
        } while (progress < 100);
        
        LOGGER.debug("Active scan completed");
    }
}
