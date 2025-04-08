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

import java.util.HashMap;
import java.util.Map;

/**
 * Scanner for web applications.
 * Provides methods for spidering and scanning web applications.
 */
public class WebAppScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebAppScanner.class);
    private static final long POLL_INTERVAL_MS = 2000;
    
    private final ClientApi zapClient;
    private final ScanConfig config;
    private AuthenticationHandler authHandler;
    
    /**
     * Creates a new web application scanner with the specified ZAP client and configuration.
     * 
     * @param zapClient The ZAP client
     * @param config The scan configuration
     */
    public WebAppScanner(ClientApi zapClient, ScanConfig config) {
        this.zapClient = zapClient;
        this.config = config;
    }
    
    /**
     * Sets the authentication handler for authenticated scanning.
     * 
     * @param authHandler The authentication handler
     */
    public void setAuthenticationHandler(AuthenticationHandler authHandler) {
        this.authHandler = authHandler;
    }
    
    /**
     * Spiders a target URL to discover content.
     * 
     * @param targetUrl The target URL
     * @param contextName The ZAP context name (optional)
     * @param maxDepth The maximum spider depth
     * @param timeoutInMinutes The maximum spider duration in minutes
     * @throws ZapScannerException If spidering fails
     */
    public void spiderTarget(String targetUrl, String contextName, int maxDepth, int timeoutInMinutes) 
            throws ZapScannerException {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new ZapScannerException("Target URL cannot be null or empty");
        }
        
        LOGGER.info("Starting spider for target URL: {}", targetUrl);
        
        try {
            // Set up authentication if needed
            Integer contextId = null;
            Integer userId = null;
            
            if (authHandler != null && contextName != null && !contextName.isEmpty()) {
                // Configure authentication
                contextId = authHandler.setupAuthentication(contextName);
                LOGGER.info("Authentication configured for context ID: {}", contextId);
            }
            
            // Start the spider
            ApiResponse response;
            String scanIdStr;
            
            if (contextId != null && userId != null) {
                // Spider as user
                Map<String, String> params = new HashMap<>();
                params.put("url", targetUrl);
                params.put("maxChildren", String.valueOf(maxDepth));
                params.put("contextName", contextName);
                params.put("userId", String.valueOf(userId));
                
                response = zapClient.spider.scan(params);
            } else {
                // Regular spider
                response = zapClient.spider.scan(targetUrl, String.valueOf(maxDepth), null, contextName, null);
            }
            
            // Extract scan ID
            scanIdStr = ((ApiResponseElement) response).getValue();
            int scanId = Integer.parseInt(scanIdStr);
            
            LOGGER.info("Spider started with ID: {}", scanId);
            
            // Wait for spider to complete
            waitForSpiderCompletion(scanId, timeoutInMinutes);
        } catch (Exception e) {
            LOGGER.error("Failed during spider", e);
            throw new ZapScannerException("Failed during spider: " + e.getMessage(), e);
        }
    }
    
    /**
     * Waits for a spider to complete.
     * 
     * @param scanId The scan ID
     * @param timeoutInMinutes The maximum wait time in minutes
     * @throws ZapScannerException If waiting fails or times out
     */
    private void waitForSpiderCompletion(int scanId, int timeoutInMinutes) throws ZapScannerException {
        long startTime = System.currentTimeMillis();
        long timeoutInMs = timeoutInMinutes * 60 * 1000;
        
        try {
            while (true) {
                // Check if spider is complete
                ApiResponse response = zapClient.spider.status(Integer.toString(scanId));
                int progress = Integer.parseInt(((ApiResponseElement) response).getValue());
                
                LOGGER.debug("Spider progress: {}%", progress);
                
                if (progress >= 100) {
                    LOGGER.info("Spider completed");
                    break;
                }
                
                // Check for timeout
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > timeoutInMs) {
                    LOGGER.warn("Spider timed out after {} minutes", timeoutInMinutes);
                    zapClient.spider.stop(Integer.toString(scanId));
                    throw new ZapScannerException("Spider timed out after " + timeoutInMinutes + " minutes");
                }
                
                // Wait before polling again
                Thread.sleep(POLL_INTERVAL_MS);
            }
        } catch (ClientApiException | InterruptedException | NumberFormatException e) {
            LOGGER.error("Failed while waiting for spider completion", e);
            throw new ZapScannerException("Failed while waiting for spider completion: " + e.getMessage(), e);
        }
    }
    
    /**
     * Performs an Ajax spider on a target URL to discover content that requires JavaScript.
     * 
     * @param targetUrl The target URL
     * @param contextName The ZAP context name (optional)
     * @param timeoutInMinutes The maximum spider duration in minutes
     * @throws ZapScannerException If spidering fails
     */
    public void ajaxSpiderTarget(String targetUrl, String contextName, int timeoutInMinutes) 
            throws ZapScannerException {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new ZapScannerException("Target URL cannot be null or empty");
        }
        
        LOGGER.info("Starting Ajax spider for target URL: {}", targetUrl);
        
        try {
            // Set up authentication if needed
            Integer contextId = null;
            
            if (authHandler != null && contextName != null && !contextName.isEmpty()) {
                // Configure authentication
                contextId = authHandler.setupAuthentication(contextName);
                LOGGER.info("Authentication configured for context ID: {}", contextId);
            }
            
            // Start the Ajax spider
            ApiResponse response = zapClient.ajaxSpider.scan(targetUrl, contextName, null, null);
            
            LOGGER.info("Ajax spider started");
            
            // Wait for Ajax spider to complete
            waitForAjaxSpiderCompletion(timeoutInMinutes);
        } catch (Exception e) {
            LOGGER.error("Failed during Ajax spider", e);
            throw new ZapScannerException("Failed during Ajax spider: " + e.getMessage(), e);
        }
    }
    
    /**
     * Waits for an Ajax spider to complete.
     * 
     * @param timeoutInMinutes The maximum wait time in minutes
     * @throws ZapScannerException If waiting fails or times out
     */
    private void waitForAjaxSpiderCompletion(int timeoutInMinutes) throws ZapScannerException {
        long startTime = System.currentTimeMillis();
        long timeoutInMs = timeoutInMinutes * 60 * 1000;
        
        try {
            while (true) {
                // Check if Ajax spider is complete
                ApiResponse response = zapClient.ajaxSpider.status();
                String status = ((ApiResponseElement) response).getValue();
                
                LOGGER.debug("Ajax spider status: {}", status);
                
                if ("stopped".equalsIgnoreCase(status)) {
                    LOGGER.info("Ajax spider completed");
                    break;
                }
                
                // Check for timeout
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > timeoutInMs) {
                    LOGGER.warn("Ajax spider timed out after {} minutes", timeoutInMinutes);
                    zapClient.ajaxSpider.stop();
                    throw new ZapScannerException("Ajax spider timed out after " + timeoutInMinutes + " minutes");
                }
                
                // Wait before polling again
                Thread.sleep(POLL_INTERVAL_MS);
            }
        } catch (ClientApiException | InterruptedException e) {
            LOGGER.error("Failed while waiting for Ajax spider completion", e);
            throw new ZapScannerException("Failed while waiting for Ajax spider completion: " + e.getMessage(), e);
        }
    }
    
    /**
     * Performs a passive scan on the spidered content.
     * 
     * @param contextName The ZAP context name (optional)
     * @param timeoutInMinutes The maximum scan duration in minutes
     * @throws ZapScannerException If scanning fails
     */
    public void performPassiveScan(String contextName, int timeoutInMinutes) throws ZapScannerException {
        LOGGER.info("Starting passive scan");
        
        try {
            // Wait for passive scanning to complete
            long startTime = System.currentTimeMillis();
            long timeoutInMs = timeoutInMinutes * 60 * 1000;
            
            while (true) {
                // Check if passive scanning is complete
                ApiResponse response = zapClient.pscan.recordsToScan();
                int recordsToScan = Integer.parseInt(((ApiResponseElement) response).getValue());
                
                LOGGER.debug("Records left to scan: {}", recordsToScan);
                
                if (recordsToScan == 0) {
                    LOGGER.info("Passive scan completed");
                    break;
                }
                
                // Check for timeout
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > timeoutInMs) {
                    LOGGER.warn("Passive scan timed out after {} minutes", timeoutInMinutes);
                    throw new ZapScannerException("Passive scan timed out after " + timeoutInMinutes + " minutes");
                }
                
                // Wait before checking again
                Thread.sleep(POLL_INTERVAL_MS);
            }
        } catch (ClientApiException | InterruptedException | NumberFormatException e) {
            LOGGER.error("Failed during passive scan", e);
            throw new ZapScannerException("Failed during passive scan: " + e.getMessage(), e);
        }
    }
    
    /**
     * Performs an active scan on the spidered content.
     * 
     * @param targetUrl The target URL
     * @param contextName The ZAP context name (optional)
     * @param scanPolicy The scan policy to use
     * @param timeoutInMinutes The maximum scan duration in minutes
     * @throws ZapScannerException If scanning fails
     */
    public void performActiveScan(String targetUrl, String contextName, ScanPolicy scanPolicy, int timeoutInMinutes) 
            throws ZapScannerException {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new ZapScannerException("Target URL cannot be null or empty");
        }
        
        LOGGER.info("Starting active scan for target URL: {}", targetUrl);
        
        try {
            // Set up authentication if needed
            Integer contextId = null;
            Integer userId = null;
            
            if (authHandler != null && contextName != null && !contextName.isEmpty()) {
                // Configure authentication
                contextId = authHandler.setupAuthentication(contextName);
                LOGGER.info("Authentication configured for context ID: {}", contextId);
                // In a real implementation, we would also get the user ID
            }
            
            // Start the active scan
            ApiResponse response;
            String scanIdStr;
            
            if (contextId != null && userId != null) {
                // Scan as user
                response = zapClient.ascan.scanAsUser(targetUrl, contextId, userId);
            } else {
                // Regular scan
                Map<String, String> params = new HashMap<>();
                params.put("url", targetUrl);
                params.put("recurse", "true");
                params.put("inScopeOnly", "false");
                
                if (contextName != null && !contextName.isEmpty()) {
                    params.put("contextName", contextName);
                }
                
                if (scanPolicy != null) {
                    params.put("scanPolicyName", scanPolicy.getName());
                }
                
                response = zapClient.ascan.scan(targetUrl, "true", "false", scanPolicy.getName(), null, null);
            }
            
            // Extract scan ID
            scanIdStr = ((ApiResponseElement) response).getValue();
            int scanId = Integer.parseInt(scanIdStr);
            
            LOGGER.info("Active scan started with ID: {}", scanId);
            
            // Configure scan policy if provided
            if (scanPolicy != null) {
                configureScanPolicy(scanId, scanPolicy);
            }
            
            // Wait for scan to complete
            waitForActiveScanCompletion(scanId, timeoutInMinutes);
        } catch (Exception e) {
            LOGGER.error("Failed during active scan", e);
            throw new ZapScannerException("Failed during active scan: " + e.getMessage(), e);
        }
    }
    
    /**
     * Configures a scan with the specified policy.
     * 
     * @param scanId The scan ID
     * @param policy The scan policy
     * @throws ClientApiException If configuration fails
     */
    private void configureScanPolicy(int scanId, ScanPolicy policy) throws ClientApiException {
        LOGGER.debug("Configuring scan policy for scan ID: {}", scanId);
        
        // In a real implementation, we would configure the scan policy
        // For this stub, we'll just log the action
        
        LOGGER.debug("Scan policy configured for scan ID: {}", scanId);
    }
    
    /**
     * Waits for an active scan to complete.
     * 
     * @param scanId The scan ID
     * @param timeoutInMinutes The maximum wait time in minutes
     * @throws ZapScannerException If waiting fails or times out
     */
    private void waitForActiveScanCompletion(int scanId, int timeoutInMinutes) throws ZapScannerException {
        long startTime = System.currentTimeMillis();
        long timeoutInMs = timeoutInMinutes * 60 * 1000;
        
        try {
            while (true) {
                // Check if scan is complete
                ApiResponse response = zapClient.ascan.status(Integer.toString(scanId));
                int progress = Integer.parseInt(((ApiResponseElement) response).getValue());
                
                LOGGER.debug("Active scan progress: {}%", progress);
                
                if (progress >= 100) {
                    LOGGER.info("Active scan completed");
                    break;
                }
                
                // Check for timeout
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > timeoutInMs) {
                    LOGGER.warn("Active scan timed out after {} minutes", timeoutInMinutes);
                    zapClient.ascan.stop(Integer.toString(scanId));
                    throw new ZapScannerException("Active scan timed out after " + timeoutInMinutes + " minutes");
                }
                
                // Wait before polling again
                Thread.sleep(POLL_INTERVAL_MS);
            }
        } catch (ClientApiException | InterruptedException | NumberFormatException e) {
            LOGGER.error("Failed while waiting for active scan completion", e);
            throw new ZapScannerException("Failed while waiting for active scan completion: " + e.getMessage(), e);
        }
    }
}
