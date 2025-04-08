package com.securitytesting.zap.example;

import com.securitytesting.zap.ZapScanner;
import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.PolicyManager;
import com.securitytesting.zap.policy.ScanPolicy;
import com.securitytesting.zap.report.RemediationReport;
import com.securitytesting.zap.report.ReportGenerator;
import com.securitytesting.zap.report.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeUnit;

/**
 * Example demonstrating the usage of the ZapScanner library.
 */
public class ScannerExample {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScannerExample.class);
    
    /**
     * Main method.
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            // Parse command line arguments
            if (args.length < 2) {
                System.out.println("Usage: java -jar zap-scanner.jar <scan-type> <target>");
                System.out.println("  scan-type: web, api, or selenium");
                System.out.println("  target: URL to scan or file path to OpenAPI spec");
                return;
            }
            
            String scanType = args[0];
            String target = args[1];
            
            // Create scan configuration
            ScanConfig config = createScanConfig();
            
            // Create ZAP scanner
            ZapScanner scanner = new ZapScanner(config);
            
            if (!scanner.isZapApiAvailable()) {
                System.err.println("ZAP API is not available. Make sure ZAP is running and accessible.");
                return;
            }
            
            // Create scan policy
            PolicyManager policyManager = scanner.getPolicyManager();
            ScanPolicy policy = policyManager.createMediumSecurityPolicy();
            
            // Run scan based on type
            ScanResult result = null;
            
            switch (scanType) {
                case "web":
                    // Scan web application
                    result = scanner.scanWebApplication(target, policy);
                    break;
                    
                case "api":
                    // Scan OpenAPI spec
                    if (target.startsWith("http://") || target.startsWith("https://")) {
                        result = scanner.scanOpenApi(new URL(target), policy);
                    } else {
                        result = scanner.scanOpenApi(new File(target), policy);
                    }
                    break;
                    
                case "selenium":
                    // Scan with Selenium (requires Chrome WebDriver path)
                    String driverPath = args.length > 2 ? args[2] : "/usr/local/bin/chromedriver";
                    result = scanner.scanWithSelenium(target, driverPath, policy);
                    break;
                    
                default:
                    System.err.println("Unknown scan type: " + scanType);
                    return;
            }
            
            // Generate reports
            if (result != null) {
                // Print summary
                printScanSummary(result);
                
                // Generate standard reports
                scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "zap-report.html");
                System.out.println("HTML report generated: zap-report.html");
                
                scanner.generateReport(result, ReportGenerator.ReportFormat.JSON, "zap-report.json");
                System.out.println("JSON report generated: zap-report.json");
                
                // Generate remediation report
                generateRemediationReport(result);
            }
            
            // Stop ZAP (optional)
            // scanner.stopZap();
            
        } catch (ZapScannerException | MalformedURLException e) {
            LOGGER.error("Error during scan", e);
            System.err.println("Error during scan: " + e.getMessage());
        }
    }
    
    /**
     * Generates remediation reports.
     *
     * @param result The scan result
     */
    private static void generateRemediationReport(ScanResult result) {
        try {
            RemediationReport remediationReport = new RemediationReport(result);
            
            // Generate HTML remediation report
            remediationReport.saveToFile("remediation-report.html", "html");
            System.out.println("Remediation HTML report generated: remediation-report.html");
            
            // Generate Markdown remediation report
            remediationReport.saveToFile("remediation-report.md", "markdown");
            System.out.println("Remediation Markdown report generated: remediation-report.md");
            
            // Print remediation suggestions count
            System.out.println("Generated " + remediationReport.getRemediationSuggestions().size() + 
                               " remediation suggestions for detected vulnerabilities");
        } catch (IOException e) {
            LOGGER.error("Failed to generate remediation report", e);
            System.err.println("Failed to generate remediation report: " + e.getMessage());
        }
    }
    
    /**
     * Creates a scan configuration.
     * 
     * @return The scan configuration
     */
    private static ScanConfig createScanConfig() {
        ScanConfig.Builder builder = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("")
                .contextName("Example Scan")
                .resetContextBeforeScan(true)
                .maxSpiderDepth(5)
                .maxSpiderDuration(10, TimeUnit.MINUTES)
                .maxPassiveScanDuration(10, TimeUnit.MINUTES)
                .maxActiveScanDuration(30, TimeUnit.MINUTES)
                .activeScanEnabled(true); // Ensure active scanning is enabled
        
        // Add authentication if needed
        AuthenticationConfig authConfig = createAuthenticationConfig();
        if (authConfig != null) {
            builder.authenticationConfig(authConfig);
        }
        
        return builder.build();
    }
    
    /**
     * Creates an authentication configuration.
     * 
     * @return The authentication configuration or null if not needed
     */
    private static AuthenticationConfig createAuthenticationConfig() {
        // Uncomment and modify one of the following blocks as needed
        
        // Form-based authentication
        /*
        return new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                .loginUrl("http://example.com/login")
                .username("user")
                .password("password")
                .usernameField("username")
                .passwordField("password")
                .loggedInIndicator("Logout")
                .loggedOutIndicator("Login")
                .build();
        */
        
        // API key authentication
        /*
        return new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.API_KEY)
                .apiKeyHeaderName("X-API-Key")
                .apiKeyValue("your-api-key")
                .build();
        */
        
        // Certificate authentication
        /*
        return new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.CERTIFICATE)
                .certificateFile("/path/to/cert.p12")
                .certificatePassword("password")
                .build();
        */
        
        // OAuth2 authentication
        /*
        return new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.OAUTH2)
                .clientId("client-id")
                .clientSecret("client-secret")
                .tokenUrl("http://example.com/oauth/token")
                .authorizationUrl("http://example.com/oauth/authorize")
                .scope("read write")
                .build();
        */
        
        return null;
    }
    
    /**
     * Prints a summary of the scan result.
     * 
     * @param result The scan result
     */
    private static void printScanSummary(ScanResult result) {
        System.out.println("\n----- Scan Summary -----");
        System.out.println("Target: " + result.getTargetUrl());
        System.out.println("Date: " + result.getScanDate());
        System.out.println("Duration: " + (result.getScanDurationMs() / 1000) + " seconds");
        System.out.println("\nAlerts:");
        System.out.println("  High Risk: " + result.getHighAlerts());
        System.out.println("  Medium Risk: " + result.getMediumAlerts());
        System.out.println("  Low Risk: " + result.getLowAlerts());
        System.out.println("  Informational: " + result.getInfoAlerts());
        System.out.println("  Total: " + result.getTotalAlerts());
        System.out.println("----------------------\n");
    }
}
