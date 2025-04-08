package com.securitytesting.zap.example;

import com.securitytesting.zap.ZapScanner;
import com.securitytesting.zap.auth.FormAuthenticationHandler;
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
import java.util.concurrent.TimeUnit;

/**
 * Example demonstrating scanning of well-known vulnerable applications.
 * 
 * This class contains examples for:
 * 1. Selenium-based scanning with authentication
 * 2. Spidering + Passive scanning
 * 3. Different approaches for various vulnerable applications
 */
public class VulnerableAppScanExample {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnerableAppScanExample.class);
    
    // Default locations of vulnerable test applications
    private static final String WEBGOAT_URL = "http://localhost:8080/WebGoat";
    private static final String DVWA_URL = "http://localhost:8080/dvwa";
    private static final String JUICESHOP_URL = "http://localhost:3000";
    private static final String BODGEIT_URL = "http://localhost:8080/bodgeit";
    
    /**
     * Main method.
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.out.println("Usage: java -jar zap-scanner.jar vulnerable-app <app-name> [chrome-driver-path]");
                System.out.println("  app-name: webgoat, dvwa, juiceshop, or bodgeit");
                System.out.println("  chrome-driver-path: Path to chromedriver (optional, default: /usr/local/bin/chromedriver)");
                return;
            }
            
            String appName = args[0];
            String chromeDriverPath = args.length > 1 ? args[1] : "/usr/local/bin/chromedriver";
            
            // Select the appropriate scan based on the application
            switch (appName.toLowerCase()) {
                case "webgoat":
                    scanWebGoat(chromeDriverPath);
                    break;
                case "dvwa":
                    scanDVWA(chromeDriverPath);
                    break;
                case "juiceshop":
                    scanJuiceShop(chromeDriverPath);
                    break;
                case "bodgeit":
                    scanBodgeIt(chromeDriverPath);
                    break;
                default:
                    System.err.println("Unknown application: " + appName);
                    System.out.println("Supported applications: webgoat, dvwa, juiceshop, bodgeit");
                    return;
            }
            
        } catch (Exception e) {
            LOGGER.error("Error during vulnerable app scan", e);
            System.err.println("Error during scan: " + e.getMessage());
        }
    }
    
    /**
     * Scans OWASP WebGoat using Selenium with authentication.
     * 
     * WebGoat requires authentication and has complex JavaScript-based interfaces,
     * making it an ideal candidate for Selenium-based scanning.
     * 
     * @param chromeDriverPath Path to the Chrome WebDriver
     * @throws ZapScannerException If there's an error during scanning
     */
    private static void scanWebGoat(String chromeDriverPath) throws ZapScannerException {
        System.out.println("Starting WebGoat scan with Selenium...");
        
        // Create scan config with authentication for WebGoat
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("")
                .contextName("WebGoat Scan")
                .resetContextBeforeScan(true)
                .maxSpiderDepth(5)
                .maxSpiderDuration(10, TimeUnit.MINUTES)
                .maxPassiveScanDuration(15, TimeUnit.MINUTES) // Extended passive scan
                .maxActiveScanDuration(30, TimeUnit.MINUTES)
                .activeScanEnabled(true)
                .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                        .loginUrl(WEBGOAT_URL + "/login")
                        .username("guest")
                        .password("guest")
                        .usernameField("username")
                        .passwordField("password")
                        .loggedInIndicator("Logout")
                        .loggedOutIndicator("Sign in")
                        .build())
                .build();
        
        // Create scanner and check ZAP availability
        ZapScanner scanner = new ZapScanner(config);
        if (!scanner.isZapApiAvailable()) {
            System.err.println("ZAP API is not available. Make sure ZAP is running and accessible.");
            return;
        }
        
        // Create scan policy - Using high security policy for WebGoat
        PolicyManager policyManager = scanner.getPolicyManager();
        ScanPolicy policy = policyManager.createHighSecurityPolicy();
        
        try {
            // Perform Selenium-based scan
            ScanResult result = scanner.scanWithSelenium(WEBGOAT_URL, chromeDriverPath, policy);
            
            // Generate and display reports
            generateReports(scanner, result, "webgoat");
            
        } catch (Exception e) {
            LOGGER.error("WebGoat scan failed", e);
            System.err.println("WebGoat scan failed: " + e.getMessage());
        }
    }
    
    /**
     * Scans DVWA (Damn Vulnerable Web Application) using spider + passive scan.
     * 
     * This example demonstrates how to perform a focused passive scan after spidering.
     * 
     * @param chromeDriverPath Path to the Chrome WebDriver
     * @throws ZapScannerException If there's an error during scanning
     */
    private static void scanDVWA(String chromeDriverPath) throws ZapScannerException {
        System.out.println("Starting DVWA scan with spidering and passive scan...");
        
        // DVWA has a relatively simple form-based authentication
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("")
                .contextName("DVWA Scan")
                .resetContextBeforeScan(true)
                .maxSpiderDepth(10)
                .maxSpiderDuration(15, TimeUnit.MINUTES)
                .maxPassiveScanDuration(20, TimeUnit.MINUTES) // Extended passive scan time
                .maxActiveScanDuration(5, TimeUnit.MINUTES)
                .activeScanEnabled(false) // Focusing on passive scan only
                .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                        .loginUrl(DVWA_URL + "/login.php")
                        .username("admin")
                        .password("password")
                        .usernameField("username")
                        .passwordField("password")
                        .loggedInIndicator("Logout")
                        .loggedOutIndicator("Login")
                        .build())
                .build();
        
        // Create scanner and check availability
        ZapScanner scanner = new ZapScanner(config);
        if (!scanner.isZapApiAvailable()) {
            System.err.println("ZAP API is not available. Make sure ZAP is running and accessible.");
            return;
        }
        
        // Use a medium policy for passive scanning
        PolicyManager policyManager = scanner.getPolicyManager();
        ScanPolicy policy = policyManager.createMediumSecurityPolicy();
        
        try {
            // First, authenticate using Selenium to handle complex sessions
            System.out.println("Authenticating to DVWA...");
            
            // Example of performing initial authentication with Selenium
            // Then using Spider to crawl and Passive scan to analyze
            scanner.authenticateWithSelenium(DVWA_URL, chromeDriverPath);
            
            // Now use the web scanner (Spider + Passive scan)
            System.out.println("Starting spider and passive scan...");
            ScanResult result = scanner.scanWebApplication(DVWA_URL, policy);
            
            // Generate reports
            generateReports(scanner, result, "dvwa");
            
        } catch (Exception e) {
            LOGGER.error("DVWA scan failed", e);
            System.err.println("DVWA scan failed: " + e.getMessage());
        }
    }
    
    /**
     * Scans OWASP Juice Shop using Selenium with authentication.
     * 
     * Juice Shop is a modern single-page application (SPA) with complex JavaScript,
     * making it ideal for Selenium-based scanning.
     * 
     * @param chromeDriverPath Path to the Chrome WebDriver
     * @throws ZapScannerException If there's an error during scanning
     */
    private static void scanJuiceShop(String chromeDriverPath) throws ZapScannerException {
        System.out.println("Starting Juice Shop scan with Selenium...");
        
        // Create scan config with authentication for Juice Shop
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("")
                .contextName("Juice Shop Scan")
                .resetContextBeforeScan(true)
                .maxSpiderDepth(10)
                .maxSpiderDuration(15, TimeUnit.MINUTES)
                .maxPassiveScanDuration(15, TimeUnit.MINUTES)
                .maxActiveScanDuration(30, TimeUnit.MINUTES)
                .activeScanEnabled(true)
                .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                        .loginUrl(JUICESHOP_URL + "/#/login")
                        .username("user@juice-sh.op")
                        .password("password123")
                        .usernameField("email")
                        .passwordField("password")
                        .loggedInIndicator("Your Basket")
                        .loggedOutIndicator("Login")
                        .build())
                .build();
        
        // Create scanner and check ZAP availability
        ZapScanner scanner = new ZapScanner(config);
        if (!scanner.isZapApiAvailable()) {
            System.err.println("ZAP API is not available. Make sure ZAP is running and accessible.");
            return;
        }
        
        // Create scan policy
        PolicyManager policyManager = scanner.getPolicyManager();
        ScanPolicy policy = policyManager.createHighSecurityPolicy();
        
        try {
            // Perform Selenium-based scan for better JS handling
            ScanResult result = scanner.scanWithSelenium(JUICESHOP_URL, chromeDriverPath, policy);
            
            // Generate reports
            generateReports(scanner, result, "juiceshop");
            
        } catch (Exception e) {
            LOGGER.error("Juice Shop scan failed", e);
            System.err.println("Juice Shop scan failed: " + e.getMessage());
        }
    }
    
    /**
     * Scans the BodgeIt Store using spidering and passive scanning.
     * 
     * BodgeIt is a simpler application that can be effectively scanned using
     * the traditional spider + passive scan approach.
     * 
     * @param chromeDriverPath Path to the Chrome WebDriver
     * @throws ZapScannerException If there's an error during scanning
     */
    private static void scanBodgeIt(String chromeDriverPath) throws ZapScannerException {
        System.out.println("Starting BodgeIt scan with spider and passive scan...");
        
        // Simple configuration for BodgeIt
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("")
                .contextName("BodgeIt Scan")
                .resetContextBeforeScan(true)
                .maxSpiderDepth(5)
                .maxSpiderDuration(10, TimeUnit.MINUTES)
                .maxPassiveScanDuration(20, TimeUnit.MINUTES) // Focus on passive scanning
                .maxActiveScanDuration(5, TimeUnit.MINUTES)
                .activeScanEnabled(false) // Only passive scanning for this example
                .build();
        
        // Create scanner and check availability
        ZapScanner scanner = new ZapScanner(config);
        if (!scanner.isZapApiAvailable()) {
            System.err.println("ZAP API is not available. Make sure ZAP is running and accessible.");
            return;
        }
        
        // Create policy focused on passive scan rules
        PolicyManager policyManager = scanner.getPolicyManager();
        ScanPolicy policy = policyManager.createMediumSecurityPolicy();
        
        try {
            // Perform web application scan (Spider + Passive scan)
            ScanResult result = scanner.scanWebApplication(BODGEIT_URL, policy);
            
            // Generate reports
            generateReports(scanner, result, "bodgeit");
            
        } catch (Exception e) {
            LOGGER.error("BodgeIt scan failed", e);
            System.err.println("BodgeIt scan failed: " + e.getMessage());
        }
    }
    
    /**
     * Generates standard and remediation reports for a scan.
     * 
     * @param scanner The ZAP scanner
     * @param result The scan result
     * @param appPrefix Prefix for report filenames
     */
    private static void generateReports(ZapScanner scanner, ScanResult result, String appPrefix) {
        if (result == null) {
            System.err.println("No scan results to report");
            return;
        }
        
        try {
            // Print summary
            printScanSummary(result);
            
            // Generate standard reports
            String htmlReport = appPrefix + "-zap-report.html";
            scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, htmlReport);
            System.out.println("HTML report generated: " + htmlReport);
            
            String jsonReport = appPrefix + "-zap-report.json";
            scanner.generateReport(result, ReportGenerator.ReportFormat.JSON, jsonReport);
            System.out.println("JSON report generated: " + jsonReport);
            
            // Generate remediation report
            generateRemediationReport(result, appPrefix);
            
        } catch (Exception e) {
            LOGGER.error("Failed to generate reports", e);
            System.err.println("Failed to generate reports: " + e.getMessage());
        }
    }
    
    /**
     * Generates remediation reports.
     *
     * @param result The scan result
     * @param appPrefix Prefix for report filenames
     */
    private static void generateRemediationReport(ScanResult result, String appPrefix) {
        try {
            RemediationReport remediationReport = new RemediationReport(result);
            
            // Generate HTML remediation report
            String htmlRemediation = appPrefix + "-remediation.html";
            remediationReport.saveToFile(htmlRemediation, "html");
            System.out.println("Remediation HTML report generated: " + htmlRemediation);
            
            // Generate Markdown remediation report
            String mdRemediation = appPrefix + "-remediation.md";
            remediationReport.saveToFile(mdRemediation, "markdown");
            System.out.println("Remediation Markdown report generated: " + mdRemediation);
            
            // Print remediation suggestions count
            System.out.println("Generated " + remediationReport.getRemediationSuggestions().size() + 
                               " remediation suggestions for detected vulnerabilities");
        } catch (IOException e) {
            LOGGER.error("Failed to generate remediation report", e);
            System.err.println("Failed to generate remediation report: " + e.getMessage());
        }
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