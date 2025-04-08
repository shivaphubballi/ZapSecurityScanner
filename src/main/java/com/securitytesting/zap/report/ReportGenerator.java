package com.securitytesting.zap.report;

import com.securitytesting.zap.exception.ZapScannerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Generates security scan reports in various formats.
 */
public class ReportGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportGenerator.class);
    private final ClientApi zapClient;
    
    // Default report templates
    private static final String DEFAULT_HTML_TEMPLATE = "traditional-html";
    private static final String DEFAULT_XML_TEMPLATE = "xml";
    private static final String DEFAULT_JSON_TEMPLATE = "json";
    private static final String DEFAULT_MARKDOWN_TEMPLATE = "markdown";
    private static final String DEFAULT_PDF_TEMPLATE = "traditional-pdf";
    
    /**
     * Creates a new report generator with the specified ZAP client.
     * 
     * @param zapClient The ZAP client
     */
    public ReportGenerator(ClientApi zapClient) {
        this.zapClient = zapClient;
    }
    
    /**
     * Generates an HTML report.
     * 
     * @param title The report title
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generateHtmlReport(String title, String outputPath) throws ZapScannerException {
        return generateReport(title, DEFAULT_HTML_TEMPLATE, "html", outputPath);
    }
    
    /**
     * Generates an XML report.
     * 
     * @param title The report title
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generateXmlReport(String title, String outputPath) throws ZapScannerException {
        return generateReport(title, DEFAULT_XML_TEMPLATE, "xml", outputPath);
    }
    
    /**
     * Generates a JSON report.
     * 
     * @param title The report title
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generateJsonReport(String title, String outputPath) throws ZapScannerException {
        return generateReport(title, DEFAULT_JSON_TEMPLATE, "json", outputPath);
    }
    
    /**
     * Generates a markdown report.
     * 
     * @param title The report title
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generateMarkdownReport(String title, String outputPath) throws ZapScannerException {
        return generateReport(title, DEFAULT_MARKDOWN_TEMPLATE, "md", outputPath);
    }
    
    /**
     * Generates a PDF report.
     * 
     * @param title The report title
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generatePdfReport(String title, String outputPath) throws ZapScannerException {
        return generateReport(title, DEFAULT_PDF_TEMPLATE, "pdf", outputPath);
    }
    
    /**
     * Generates a report with the specified template and format.
     * 
     * @param title The report title
     * @param template The report template name
     * @param format The report file format extension
     * @param outputPath The output path for the report file (not including file name)
     * @return The path to the generated report
     * @throws ZapScannerException If report generation fails
     */
    public Path generateReport(String title, String template, String format, String outputPath) 
            throws ZapScannerException {
        try {
            // Create output directory if it doesn't exist
            Path directoryPath = Paths.get(outputPath);
            Files.createDirectories(directoryPath);
            
            // Generate timestamp-based filename
            String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            String fileName = String.format("zap-scan-report-%s.%s", timestamp, format);
            Path reportPath = directoryPath.resolve(fileName);
            
            // Generate report
            LOGGER.info("Generating {} report using template: {}", format.toUpperCase(), template);
            
            ApiResponse response = zapClient.reports.generate(
                title,
                template,
                null,  // theme
                "Automated security scan report generated by ZAP Scanner",  // description
                null,  // contexts
                null,  // sites
                null,  // sections
                null,  // includedConfidences
                null,  // includedRisks
                reportPath.getFileName().toString(),  // reportFileName
                null,  // reportFileNamePattern
                reportPath.getParent().toString(),  // reportDir
                "false"  // display
            );
            
            LOGGER.debug("Report generation response: {}", response);
            
            if (!Files.exists(reportPath)) {
                throw new ZapScannerException("Report file was not created at: " + reportPath);
            }
            
            LOGGER.info("Report successfully generated: {}", reportPath);
            return reportPath;
            
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to generate {} report", format, e);
            throw new ZapScannerException("Failed to generate report: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets all alerts from the ZAP session.
     * 
     * @return A list of alerts
     * @throws ZapScannerException If retrieving alerts fails
     */
    public List<Alert> getAlerts() throws ZapScannerException {
        try {
            ApiResponse response = zapClient.core.alerts(null, 0, 0);
            // Parse the response and convert to Alert objects
            // This is a simplified implementation
            List<Alert> alerts = new ArrayList<>();
            // Actual implementation would parse the response JSON/XML
            return alerts;
        } catch (ClientApiException e) {
            LOGGER.error("Failed to retrieve alerts", e);
            throw new ZapScannerException("Failed to retrieve alerts: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets alerts filtered by severity.
     * 
     * @param severity The severity level
     * @return A list of alerts with the specified severity
     * @throws ZapScannerException If retrieving alerts fails
     */
    public List<Alert> getAlertsBySeverity(Severity severity) throws ZapScannerException {
        List<Alert> allAlerts = getAlerts();
        return allAlerts.stream()
                .filter(alert -> alert.getSeverity() == severity)
                .collect(Collectors.toList());
    }
    
    /**
     * Gets a summary of alerts grouped by severity.
     * 
     * @return A summary of alerts
     * @throws ZapScannerException If retrieving alerts fails
     */
    public ScanResult getScanResult() throws ZapScannerException {
        List<Alert> alerts = getAlerts();
        ScanResult result = new ScanResult();
        
        // Group alerts by severity
        for (Alert alert : alerts) {
            switch (alert.getSeverity()) {
                case HIGH:
                    result.incrementHighAlerts();
                    break;
                case MEDIUM:
                    result.incrementMediumAlerts();
                    break;
                case LOW:
                    result.incrementLowAlerts();
                    break;
                case INFORMATIONAL:
                    result.incrementInfoAlerts();
                    break;
            }
        }
        
        result.setTotalAlerts(alerts.size());
        result.setAlerts(alerts);
        return result;
    }
    
    /**
     * Exports alerts to a file in the specified format.
     * 
     * @param outputPath The path where the file should be saved
     * @param format The format (json, xml, etc.)
     * @return The path to the exported file
     * @throws ZapScannerException If exporting fails
     */
    public Path exportAlerts(String outputPath, String format) throws ZapScannerException {
        try {
            Path filePath = Paths.get(outputPath);
            Files.createDirectories(filePath.getParent());
            
            // Use the ZAP API to export alerts
            // This is a simplified implementation
            List<Alert> alerts = getAlerts();
            
            // Write alerts to file based on format
            // Actual implementation would use proper serialization
            
            return filePath;
        } catch (IOException e) {
            LOGGER.error("Failed to export alerts", e);
            throw new ZapScannerException("Failed to export alerts: " + e.getMessage(), e);
        }
    }
}
