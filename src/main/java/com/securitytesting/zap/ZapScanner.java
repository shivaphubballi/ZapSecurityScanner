package com.securitytesting.zap;

import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.report.ReportGenerator;
import com.securitytesting.zap.report.ScanResult;
import com.securitytesting.zap.scanner.OpenApiScanner;
import com.securitytesting.zap.scanner.SeleniumScanner;
import com.securitytesting.zap.scanner.WebAppScanner;
import com.securitytesting.zap.util.ZapClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;

import java.util.Objects;

/**
 * Main entry point for the ZAP Security Scanner library.
 * Provides methods to perform various types of security scans.
 */
public class ZapScanner implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanner.class);

    private final ClientApi zapClient;
    private final WebAppScanner webAppScanner;
    private final OpenApiScanner openApiScanner;
    private final SeleniumScanner seleniumScanner;
    private final ReportGenerator reportGenerator;

    /**
     * Creates a new ZapScanner instance with the specified ZAP proxy address.
     *
     * @param zapAddress ZAP proxy address in format "host:port"
     * @param apiKey     API key for the ZAP instance (or null if not required)
     * @throws ZapScannerException if connection to ZAP fails
     */
    public ZapScanner(String zapAddress, String apiKey) throws ZapScannerException {
        LOGGER.info("Initializing ZAP Scanner with proxy at {}", zapAddress);
        this.zapClient = ZapClientFactory.createZapClient(zapAddress, apiKey);
        this.webAppScanner = new WebAppScanner(zapClient);
        this.openApiScanner = new OpenApiScanner(zapClient);
        this.seleniumScanner = new SeleniumScanner(zapClient);
        this.reportGenerator = new ReportGenerator(zapClient);
    }

    /**
     * Performs a security scan on a web application.
     *
     * @param config The scan configuration
     * @return ScanResult containing the findings
     * @throws ZapScannerException if the scan fails
     */
    public ScanResult scanWebApplication(ScanConfig config) throws ZapScannerException {
        Objects.requireNonNull(config, "Scan configuration cannot be null");
        LOGGER.info("Starting web application security scan for: {}", config.getTargetUrl());
        
        try {
            webAppScanner.scan(config);
            return reportGenerator.generateReport(config.getTargetUrl());
        } catch (Exception e) {
            LOGGER.error("Error during web application scan", e);
            throw new ZapScannerException("Failed to perform web application scan", e);
        }
    }

    /**
     * Performs a security scan based on OpenAPI specification.
     *
     * @param config              The scan configuration
     * @param openApiSpecLocation URL or file path to the OpenAPI specification
     * @return ScanResult containing the findings
     * @throws ZapScannerException if the scan fails
     */
    public ScanResult scanOpenApi(ScanConfig config, String openApiSpecLocation) throws ZapScannerException {
        Objects.requireNonNull(config, "Scan configuration cannot be null");
        Objects.requireNonNull(openApiSpecLocation, "OpenAPI specification location cannot be null");
        LOGGER.info("Starting OpenAPI security scan for spec: {}", openApiSpecLocation);
        
        try {
            openApiScanner.scan(config, openApiSpecLocation);
            return reportGenerator.generateReport(config.getTargetUrl());
        } catch (Exception e) {
            LOGGER.error("Error during OpenAPI scan", e);
            throw new ZapScannerException("Failed to perform OpenAPI scan", e);
        }
    }

    /**
     * Performs a security scan using Selenium for dynamic application testing.
     *
     * @param config     The scan configuration
     * @param scriptPath Path to the Selenium script file
     * @return ScanResult containing the findings
     * @throws ZapScannerException if the scan fails
     */
    public ScanResult scanWithSelenium(ScanConfig config, String scriptPath) throws ZapScannerException {
        Objects.requireNonNull(config, "Scan configuration cannot be null");
        Objects.requireNonNull(scriptPath, "Selenium script path cannot be null");
        LOGGER.info("Starting Selenium-driven security scan using script: {}", scriptPath);
        
        try {
            seleniumScanner.scan(config, scriptPath);
            return reportGenerator.generateReport(config.getTargetUrl());
        } catch (Exception e) {
            LOGGER.error("Error during Selenium scan", e);
            throw new ZapScannerException("Failed to perform Selenium scan", e);
        }
    }

    /**
     * Gets a direct reference to the ZAP API client for advanced operations.
     *
     * @return ClientApi instance
     */
    public ClientApi getZapClient() {
        return zapClient;
    }

    /**
     * Shuts down the scanner and releases any resources.
     */
    @Override
    public void close() {
        LOGGER.info("Shutting down ZAP Scanner");
        // Additional cleanup if needed
    }
}
