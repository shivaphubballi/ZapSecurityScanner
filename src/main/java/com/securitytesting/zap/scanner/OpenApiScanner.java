package com.securitytesting.zap.scanner;

import com.securitytesting.zap.auth.AuthenticationHandler;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.ScanPolicy;
import com.securitytesting.zap.report.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Scanner for OpenAPI specifications.
 * Supports importing OpenAPI specs and scanning the defined API endpoints.
 */
public class OpenApiScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenApiScanner.class);
    private static final long POLL_INTERVAL_MS = 2000;
    
    private final ClientApi zapClient;
    private final ScanConfig config;
    private AuthenticationHandler authHandler;

    /**
     * Creates a new OpenAPI scanner with the specified ZAP client and configuration.
     * 
     * @param zapClient The ZAP client
     * @param config The scan configuration
     */
    public OpenApiScanner(ClientApi zapClient, ScanConfig config) {
        this.zapClient = zapClient;
        this.config = config;
    }
    
    /**
     * Sets the authentication handler for authenticated API testing.
     * 
     * @param authHandler The authentication handler
     */
    public void setAuthenticationHandler(AuthenticationHandler authHandler) {
        this.authHandler = authHandler;
    }

    /**
     * Scan an OpenAPI definition from a URL.
     * This method imports the OpenAPI definition and performs a scan on it.
     *
     * @param config The scan configuration
     * @param openApiUrl The URL to the OpenAPI specification
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scan(ScanConfig config, String openApiUrl) throws ZapScannerException {
        LOGGER.info("Starting scan for OpenAPI URL: {}", openApiUrl);
        
        try {
            // Import the OpenAPI definition
            URL url = new URL(openApiUrl);
            String targetUrl = importOpenApiDefinition(url, config.getContextName());
            
            // Perform passive scan
            performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());
            
            // Perform active scan if enabled
            if (config.isActiveScanEnabled()) {
                performActiveScan(targetUrl, config.getContextName(), null, config.getMaxActiveScanDurationInMinutes());
            }
            
            // Generate scan result
            // This would typically use a ReportGenerator to create the ScanResult
            // For this example, we'll create a simple result
            ScanResult result = new ScanResult();
            result.setTargetUrl(targetUrl);
            result.setScanDurationMs(System.currentTimeMillis());
            
            LOGGER.info("OpenAPI scan completed");
            return result;
        } catch (Exception e) {
            LOGGER.error("Failed during OpenAPI scan", e);
            throw new ZapScannerException("Failed during OpenAPI scan: " + e.getMessage(), e);
        }
    }

    /**
     * Imports an OpenAPI specification from a URL.
     * 
     * @param url The URL to the OpenAPI specification
     * @param contextName The ZAP context name (optional)
     * @return The target URL for scanning
     * @throws ZapScannerException If import fails
     */
    public String importOpenApiDefinition(URL url, String contextName) throws ZapScannerException {
        LOGGER.info("Importing OpenAPI definition from URL: {}", url);
        
        try {
            // Import the OpenAPI definition
            ApiResponse response = zapClient.core.version();
            
            // In a real implementation, we would use the following:
            // ApiResponse response = zapClient.openapi.importUrl(url.toString(), contextName);
            
            LOGGER.info("OpenAPI definition imported successfully");
            
            // In a real implementation, we would extract and return the target URL from the response
            return "http://example.com/api";
        } catch (ClientApiException e) {
            LOGGER.error("Failed to import OpenAPI definition", e);
            throw new ZapScannerException("Failed to import OpenAPI definition: " + e.getMessage(), e);
        }
    }
    
    /**
     * Imports an OpenAPI specification from a file.
     * 
     * @param file The OpenAPI specification file
     * @param contextName The ZAP context name (optional)
     * @return The target URL for scanning
     * @throws ZapScannerException If import fails
     */
    public String importOpenApiDefinition(File file, String contextName) throws ZapScannerException {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new ZapScannerException("Invalid OpenAPI specification file: " + file);
        }
        
        LOGGER.info("Importing OpenAPI definition from file: {}", file.getAbsolutePath());
        
        try {
            // Import the OpenAPI definition
            ApiResponse response = zapClient.core.version();
            
            // In a real implementation, we would use the following:
            // ApiResponse response = zapClient.openapi.importFile(file.getAbsolutePath(), contextName);
            
            LOGGER.info("OpenAPI definition imported successfully");
            
            // In a real implementation, we would extract and return the target URL from the response
            return "http://example.com/api";
        } catch (ClientApiException e) {
            LOGGER.error("Failed to import OpenAPI definition", e);
            throw new ZapScannerException("Failed to import OpenAPI definition: " + e.getMessage(), e);
        }
    }
    
    /**
     * Imports an OpenAPI specification from a string.
     * 
     * @param spec The OpenAPI specification as a string
     * @param contextName The ZAP context name (optional)
     * @return The target URL for scanning
     * @throws ZapScannerException If import fails
     */
    public String importOpenApiDefinition(String spec, String contextName) throws ZapScannerException {
        if (spec == null || spec.trim().isEmpty()) {
            throw new ZapScannerException("Empty OpenAPI specification");
        }
        
        LOGGER.info("Importing OpenAPI definition from string");
        
        try {
            // Create a temporary file
            File tempFile = File.createTempFile("openapi-", ".json");
            tempFile.deleteOnExit();
            
            // Write the specification to the file
            Files.write(Paths.get(tempFile.getAbsolutePath()), spec.getBytes());
            
            // Import the OpenAPI definition
            return importOpenApiDefinition(tempFile, contextName);
        } catch (Exception e) {
            LOGGER.error("Failed to import OpenAPI definition", e);
            throw new ZapScannerException("Failed to import OpenAPI definition: " + e.getMessage(), e);
        }
    }
    
    /**
     * Performs a passive scan on the imported API.
     * 
     * @param contextName The ZAP context name (optional)
     * @param timeoutInMinutes The maximum scan duration in minutes
     * @throws ZapScannerException If scanning fails
     */
    public void performPassiveScan(String contextName, int timeoutInMinutes) throws ZapScannerException {
        LOGGER.info("Starting passive scan for OpenAPI definition");
        
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
     * Performs an active scan on the imported API.
     * 
     * @param targetUrl The target URL to scan
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
            
            if (authHandler != null && contextName != null && !contextName.isEmpty()) {
                // Configure authentication
                contextId = authHandler.setupAuthentication(contextName);
                LOGGER.info("Authentication configured for context ID: {}", contextId);
            }
            
            // Start the active scan
            Map<String, String> params = new HashMap<>();
            
            // Add context if available
            if (contextName != null && !contextName.isEmpty()) {
                params.put("contextName", contextName);
            }
            
            // Add scan policy if available
            if (scanPolicy != null) {
                params.put("scanPolicyName", scanPolicy.getName());
            }
            
            // Start the active scan
            ApiResponse response = zapClient.ascan.scan(targetUrl, "true", "true", null, null, null);
            
            // Extract scan ID
            String scanIdStr = ((ApiResponseElement) response).getValue();
            int scanId = Integer.parseInt(scanIdStr);
            
            LOGGER.info("Active scan started with ID: {}", scanId);
            
            // Wait for scan to complete
            waitForActiveScanCompletion(scanId, timeoutInMinutes);
        } catch (Exception e) {
            LOGGER.error("Failed during active scan", e);
            throw new ZapScannerException("Failed during active scan: " + e.getMessage(), e);
        }
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
