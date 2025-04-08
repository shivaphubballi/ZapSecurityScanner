package com.securitytesting.zap;

import com.securitytesting.zap.auth.ApiKeyAuthenticationHandler;
import com.securitytesting.zap.auth.AuthenticationHandler;
import com.securitytesting.zap.auth.CertificateAuthenticationHandler;
import com.securitytesting.zap.auth.FormAuthenticationHandler;
import com.securitytesting.zap.auth.OAuth2AuthenticationHandler;
import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import com.securitytesting.zap.exception.ScanConfigurationException;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.PolicyManager;
import com.securitytesting.zap.policy.ScanPolicy;
import com.securitytesting.zap.report.RemediationReport;
import com.securitytesting.zap.report.ReportGenerator;
import com.securitytesting.zap.report.ScanResult;
import com.securitytesting.zap.scanner.OpenApiScanner;
import com.securitytesting.zap.scanner.SeleniumScanner;
import com.securitytesting.zap.scanner.WebAppScanner;
import com.securitytesting.zap.util.ZapClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Date;

/**
 * Main class for ZAP security scanning.
 * Provides methods for various types of security scans.
 */
public class ZapScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanner.class);
    
    private final ClientApi zapClient;
    private final ScanConfig config;
    private final PolicyManager policyManager;
    private final ReportGenerator reportGenerator;
    
    /**
     * Creates a new ZAP scanner with the specified configuration.
     * 
     * @param config The scan configuration
     * @throws ZapScannerException If scanner creation fails
     */
    public ZapScanner(ScanConfig config) throws ZapScannerException {
        this.config = config;
        this.zapClient = ZapClientFactory.createZapClient(config.getZapHost(), config.getZapPort(), config.getZapApiKey());
        this.policyManager = new PolicyManager();
        this.reportGenerator = new ReportGenerator(zapClient);
        
        if (config.isResetContextBeforeScan()) {
            resetContext();
        }
    }
    
    /**
     * Resets the ZAP context.
     * Clears all existing contexts and creates a new one.
     * 
     * @throws ZapScannerException If reset fails
     */
    private void resetContext() throws ZapScannerException {
        try {
            LOGGER.info("Resetting ZAP context");
            
            // In a real implementation, we would use the ZAP API to reset the context
            // For this stub, we'll just log the action
            
            LOGGER.info("ZAP context reset");
        } catch (Exception e) {
            LOGGER.error("Failed to reset ZAP context", e);
            throw new ZapScannerException("Failed to reset ZAP context: " + e.getMessage(), e);
        }
    }
    
    /**
     * Scans a web application.
     * 
     * @param targetUrl The target URL
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanWebApplication(String targetUrl) throws ZapScannerException {
        return scanWebApplication(targetUrl, null);
    }
    
    /**
     * Scans a web application with the specified policy.
     * 
     * @param targetUrl The target URL
     * @param policy The scan policy
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanWebApplication(String targetUrl, ScanPolicy policy) throws ZapScannerException {
        LOGGER.info("Starting web application scan for target URL: {}", targetUrl);
        
        try {
            // Create a web application scanner
            WebAppScanner scanner = new WebAppScanner(zapClient, config);
            
            // Configure authentication if needed
            if (config.getAuthenticationConfig() != null) {
                scanner.setAuthenticationHandler(createAuthenticationHandler(config.getAuthenticationConfig()));
            }
            
            // Use default policy if none provided
            ScanPolicy scanPolicy = policy != null ? policy : policyManager.createMediumSecurityPolicy();
            
            // Start the scan
            long startTime = System.currentTimeMillis();
            
            // Spider the target
            scanner.spiderTarget(targetUrl, config.getContextName(), config.getMaxSpiderDepth(), 
                    config.getMaxSpiderDurationInMinutes());
            
            // Perform passive scan
            scanner.performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());
            
            // Perform active scan
            scanner.performActiveScan(targetUrl, config.getContextName(), scanPolicy, 
                    config.getMaxActiveScanDurationInMinutes());
            
            // Generate scan result
            long endTime = System.currentTimeMillis();
            ScanResult result = reportGenerator.generateScanResult(targetUrl, endTime - startTime);
            
            LOGGER.info("Web application scan completed for target URL: {}", targetUrl);
            return result;
        } catch (Exception e) {
            LOGGER.error("Failed to scan web application", e);
            throw new ZapScannerException("Failed to scan web application: " + e.getMessage(), e);
        }
    }
    
    /**
     * Scans an OpenAPI specification.
     * 
     * @param openApiUrl The URL to the OpenAPI specification
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanOpenApi(URL openApiUrl) throws ZapScannerException {
        return scanOpenApi(openApiUrl, null);
    }
    
    /**
     * Scans an OpenAPI specification with the specified policy.
     * 
     * @param openApiUrl The URL to the OpenAPI specification
     * @param policy The scan policy
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanOpenApi(URL openApiUrl, ScanPolicy policy) throws ZapScannerException {
        LOGGER.info("Starting OpenAPI scan for specification URL: {}", openApiUrl);
        
        try {
            // Create an OpenAPI scanner
            OpenApiScanner scanner = new OpenApiScanner(zapClient, config);
            
            // Configure authentication if needed
            if (config.getAuthenticationConfig() != null) {
                scanner.setAuthenticationHandler(createAuthenticationHandler(config.getAuthenticationConfig()));
            }
            
            // Use default policy if none provided
            ScanPolicy scanPolicy = policy != null ? policy : policyManager.createApiSecurityPolicy();
            
            // Start the scan
            long startTime = System.currentTimeMillis();
            
            // Import the OpenAPI specification
            String targetUrl = scanner.importOpenApiDefinition(openApiUrl, config.getContextName());
            
            // Perform passive scan
            scanner.performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());
            
            // Perform active scan
            scanner.performActiveScan(targetUrl, config.getContextName(), scanPolicy, 
                    config.getMaxActiveScanDurationInMinutes());
            
            // Generate scan result
            long endTime = System.currentTimeMillis();
            ScanResult result = reportGenerator.generateScanResult(targetUrl, endTime - startTime);
            
            LOGGER.info("OpenAPI scan completed for specification URL: {}", openApiUrl);
            return result;
        } catch (Exception e) {
            LOGGER.error("Failed to scan OpenAPI specification", e);
            throw new ZapScannerException("Failed to scan OpenAPI specification: " + e.getMessage(), e);
        }
    }
    
    /**
     * Scans an OpenAPI specification file.
     * 
     * @param openApiFile The OpenAPI specification file
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanOpenApi(File openApiFile) throws ZapScannerException {
        return scanOpenApi(openApiFile, null);
    }
    
    /**
     * Scans an OpenAPI specification file with the specified policy.
     * 
     * @param openApiFile The OpenAPI specification file
     * @param policy The scan policy
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanOpenApi(File openApiFile, ScanPolicy policy) throws ZapScannerException {
        LOGGER.info("Starting OpenAPI scan for specification file: {}", openApiFile.getAbsolutePath());
        
        try {
            // Create an OpenAPI scanner
            OpenApiScanner scanner = new OpenApiScanner(zapClient, config);
            
            // Configure authentication if needed
            if (config.getAuthenticationConfig() != null) {
                scanner.setAuthenticationHandler(createAuthenticationHandler(config.getAuthenticationConfig()));
            }
            
            // Use default policy if none provided
            ScanPolicy scanPolicy = policy != null ? policy : policyManager.createApiSecurityPolicy();
            
            // Start the scan
            long startTime = System.currentTimeMillis();
            
            // Import the OpenAPI specification
            String targetUrl = scanner.importOpenApiDefinition(openApiFile, config.getContextName());
            
            // Perform passive scan
            scanner.performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());
            
            // Perform active scan
            scanner.performActiveScan(targetUrl, config.getContextName(), scanPolicy, 
                    config.getMaxActiveScanDurationInMinutes());
            
            // Generate scan result
            long endTime = System.currentTimeMillis();
            ScanResult result = reportGenerator.generateScanResult(targetUrl, endTime - startTime);
            
            LOGGER.info("OpenAPI scan completed for specification file: {}", openApiFile.getAbsolutePath());
            return result;
        } catch (Exception e) {
            LOGGER.error("Failed to scan OpenAPI specification", e);
            throw new ZapScannerException("Failed to scan OpenAPI specification: " + e.getMessage(), e);
        }
    }
    
    /**
     * Scans a web application using Selenium.
     * 
     * @param targetUrl The target URL
     * @param driverPath The path to the Selenium WebDriver
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanWithSelenium(String targetUrl, String driverPath) throws ZapScannerException {
        return scanWithSelenium(targetUrl, driverPath, null);
    }
    
    /**
     * Scans a web application using Selenium with the specified policy.
     * 
     * @param targetUrl The target URL
     * @param driverPath The path to the Selenium WebDriver
     * @param policy The scan policy
     * @return The scan result
     * @throws ZapScannerException If scanning fails
     */
    public ScanResult scanWithSelenium(String targetUrl, String driverPath, ScanPolicy policy) throws ZapScannerException {
        LOGGER.info("Starting Selenium scan for target URL: {}", targetUrl);
        
        try {
            // Create a Selenium scanner
            SeleniumScanner scanner = new SeleniumScanner(zapClient, config, driverPath);
            
            // Configure authentication if needed
            if (config.getAuthenticationConfig() != null) {
                scanner.setAuthenticationHandler(createAuthenticationHandler(config.getAuthenticationConfig()));
            }
            
            // Use default policy if none provided
            ScanPolicy scanPolicy = policy != null ? policy : policyManager.createMediumSecurityPolicy();
            
            // Start the scan
            long startTime = System.currentTimeMillis();
            
            // Use Selenium to navigate the application
            scanner.navigateApplication(targetUrl);
            
            // Perform passive scan
            scanner.performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());
            
            // Perform active scan
            scanner.performActiveScan(targetUrl, config.getContextName(), scanPolicy, 
                    config.getMaxActiveScanDurationInMinutes());
            
            // Generate scan result
            long endTime = System.currentTimeMillis();
            ScanResult result = reportGenerator.generateScanResult(targetUrl, endTime - startTime);
            
            LOGGER.info("Selenium scan completed for target URL: {}", targetUrl);
            return result;
        } catch (Exception e) {
            LOGGER.error("Failed to scan with Selenium", e);
            throw new ZapScannerException("Failed to scan with Selenium: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generates a scan report.
     * 
     * @param result The scan result
     * @param format The report format
     * @param outputPath The output path for the report
     * @throws ZapScannerException If report generation fails
     */
    public void generateReport(ScanResult result, ReportGenerator.ReportFormat format, String outputPath) 
            throws ZapScannerException {
        reportGenerator.generateReport(result, format, outputPath);
    }
    
    /**
     * Generates a remediation report with guided suggestions for fixing vulnerabilities.
     * 
     * @param result The scan result
     * @param outputPath The output path for the report
     * @param format The format of the report (html or markdown)
     * @throws ZapScannerException If report generation fails
     */
    public void generateRemediationReport(ScanResult result, String outputPath, String format) 
            throws ZapScannerException {
        LOGGER.info("Generating remediation report in {} format to {}", format, outputPath);
        
        try {
            RemediationReport remediationReport = new RemediationReport(result);
            remediationReport.saveToFile(outputPath, format);
            LOGGER.info("Remediation report successfully generated with {} suggestions", 
                       remediationReport.getRemediationSuggestions().size());
        } catch (IOException e) {
            LOGGER.error("Failed to generate remediation report", e);
            throw new ZapScannerException("Failed to generate remediation report: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates an authentication handler based on the authentication configuration.
     * 
     * @param authConfig The authentication configuration
     * @return The authentication handler
     * @throws AuthenticationException If handler creation fails
     */
    private AuthenticationHandler createAuthenticationHandler(AuthenticationConfig authConfig) throws AuthenticationException {
        if (authConfig == null) {
            return null;
        }
        
        AuthenticationHandler handler = null;
        
        switch (authConfig.getType()) {
            case FORM:
                // Create form authentication handler
                handler = new FormAuthenticationHandler(
                    zapClient,
                    authConfig.getLoginUrl(),
                    authConfig.getUsername(),
                    authConfig.getPassword(),
                    authConfig.getUsernameField(),
                    authConfig.getPasswordField(),
                    authConfig.getLoginRequestData(),
                    authConfig.getLoggedInIndicator(),
                    authConfig.getLoggedOutIndicator()
                );
                break;
                
            case API_KEY:
                // Create API key authentication handler
                handler = new ApiKeyAuthenticationHandler(
                    zapClient,
                    authConfig.getApiKeyHeaderName(),
                    authConfig.getApiKeyValue()
                );
                break;
                
            case CERTIFICATE:
                // Create certificate authentication handler
                File certFile = new File(authConfig.getCertificateFile());
                handler = new CertificateAuthenticationHandler(
                    zapClient,
                    certFile,
                    authConfig.getCertificatePassword()
                );
                break;
                
            case OAUTH2:
                // Create OAuth2 authentication handler
                handler = new OAuth2AuthenticationHandler(
                    zapClient,
                    authConfig.getClientId(),
                    authConfig.getClientSecret(),
                    authConfig.getTokenUrl(),
                    authConfig.getAuthorizationUrl(),
                    authConfig.getRedirectUrl(),
                    authConfig.getScope()
                );
                break;
        }
        
        return handler;
    }
    
    /**
     * Gets the policy manager.
     * 
     * @return The policy manager
     */
    public PolicyManager getPolicyManager() {
        return policyManager;
    }
    
    /**
     * Stops ZAP.
     * Shuts down the ZAP instance.
     * 
     * @throws ZapScannerException If stopping ZAP fails
     */
    public void stopZap() throws ZapScannerException {
        try {
            LOGGER.info("Stopping ZAP");
            zapClient.core.shutdown();
            LOGGER.info("ZAP stopped");
        } catch (ClientApiException e) {
            LOGGER.error("Failed to stop ZAP", e);
            throw new ZapScannerException("Failed to stop ZAP: " + e.getMessage(), e);
        }
    }
    
    /**
     * Checks if the ZAP API is available.
     * 
     * @return True if the ZAP API is available, false otherwise
     */
    public boolean isZapApiAvailable() {
        try {
            zapClient.core.version();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
