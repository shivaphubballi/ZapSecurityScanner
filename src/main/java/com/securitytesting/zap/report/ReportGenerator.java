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
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Generates reports from scan results.
 * Supports multiple report formats and output options.
 */
public class ReportGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportGenerator.class);
    
    /**
     * Enum representing the format of a report.
     */
    public enum ReportFormat {
        HTML,
        XML,
        JSON,
        PDF,
        MD
    }
    
    private final ClientApi zapClient;
    
    /**
     * Creates a new report generator with the specified ZAP client.
     * 
     * @param zapClient The ZAP client
     */
    public ReportGenerator(ClientApi zapClient) {
        this.zapClient = zapClient;
    }
    
    /**
     * Generates a scan result from alerts.
     * 
     * @param targetUrl The target URL
     * @param scanDurationMs The scan duration in milliseconds
     * @return The scan result
     * @throws ZapScannerException If generation fails
     */
    public ScanResult generateScanResult(String targetUrl, long scanDurationMs) throws ZapScannerException {
        LOGGER.info("Generating scan result for {}", targetUrl);
        
        try {
            // Get alerts from ZAP
            ApiResponse response = zapClient.core.alerts(targetUrl, 0, -1);
            
            // Parse alerts
            List<Alert> alerts = parseAlerts(response);
            
            // Count alerts by severity
            int highAlerts = 0;
            int mediumAlerts = 0;
            int lowAlerts = 0;
            int infoAlerts = 0;
            
            for (Alert alert : alerts) {
                switch (alert.getSeverity()) {
                    case HIGH:
                        highAlerts++;
                        break;
                    case MEDIUM:
                        mediumAlerts++;
                        break;
                    case LOW:
                        lowAlerts++;
                        break;
                    case INFORMATIONAL:
                        infoAlerts++;
                        break;
                }
            }
            
            // Create the scan result
            ScanResult result = new ScanResult.Builder()
                    .targetUrl(targetUrl)
                    .scanDate(new Date())
                    .scanDurationMs(scanDurationMs)
                    .highAlerts(highAlerts)
                    .mediumAlerts(mediumAlerts)
                    .lowAlerts(lowAlerts)
                    .infoAlerts(infoAlerts)
                    .totalAlerts(alerts.size())
                    .alerts(alerts)
                    .build();
            
            LOGGER.info("Scan result generated with {} alerts", alerts.size());
            return result;
        } catch (ClientApiException e) {
            LOGGER.error("Failed to generate scan result", e);
            throw new ZapScannerException("Failed to generate scan result: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generates a report from a scan result.
     * 
     * @param result The scan result
     * @param format The format of the report
     * @param outputPath The output path for the report
     * @throws ZapScannerException If generation fails
     */
    public void generateReport(ScanResult result, ReportFormat format, String outputPath) throws ZapScannerException {
        LOGGER.info("Generating {} report to {}", format, outputPath);
        
        try {
            // Generate report description
            String description = "Scan of " + result.getTargetUrl() + " completed on " + result.getScanDate();
            
            // Generate report title
            String title = "Security Scan Report: " + result.getTargetUrl();
            
            // In a real implementation, we would use the ZAP API to generate the report
            // For this stub, we'll create a simple text report
            String template = "traditional-html";
            String reportData = "";
            
            // If using the ZAP API, we would call:
            // zapClient.reports.generate(title, template, theme, description, contexts, sites, sections, includedConfidences, includedRisks, reportFileName, reportFileNamePattern, reportDir, display);
            
            // Generate a report from the scan result
            switch (format) {
                case HTML:
                    reportData = generateHtmlReport(result);
                    break;
                case XML:
                    reportData = generateXmlReport(result);
                    break;
                case JSON:
                    reportData = generateJsonReport(result);
                    break;
                case PDF:
                    reportData = generatePdfReport(result);
                    break;
                case MD:
                    reportData = generateMarkdownReport(result);
                    break;
                default:
                    throw new ZapScannerException("Unsupported report format: " + format);
            }
            
            // Save the report to the output path
            writeReportToFile(reportData, outputPath);
            
            LOGGER.info("Report generated successfully");
        } catch (Exception e) {
            LOGGER.error("Failed to generate report", e);
            throw new ZapScannerException("Failed to generate report: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses alerts from an API response.
     * 
     * @param response The API response
     * @return The list of alerts
     */
    private List<Alert> parseAlerts(ApiResponse response) {
        List<Alert> alerts = new ArrayList<>();
        
        // In a real implementation, we would parse the API response to extract alerts
        // For this stub, we'll return an empty list
        
        return alerts;
    }
    
    /**
     * Generates an HTML report from a scan result.
     * 
     * @param result The scan result
     * @return The HTML report
     */
    private String generateHtmlReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("<!DOCTYPE html>\n");
        sb.append("<html>\n");
        sb.append("<head>\n");
        sb.append("  <title>Security Scan Report: ").append(result.getTargetUrl()).append("</title>\n");
        sb.append("  <style>\n");
        sb.append("    body { font-family: Arial, sans-serif; }\n");
        sb.append("    .summary { margin-bottom: 20px; }\n");
        sb.append("    .alert { margin-bottom: 10px; border: 1px solid #ccc; padding: 10px; }\n");
        sb.append("    .high { border-left: 5px solid #d9534f; }\n");
        sb.append("    .medium { border-left: 5px solid #f0ad4e; }\n");
        sb.append("    .low { border-left: 5px solid #5bc0de; }\n");
        sb.append("    .info { border-left: 5px solid #5cb85c; }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n");
        sb.append("<body>\n");
        
        // Summary
        sb.append("  <div class=\"summary\">\n");
        sb.append("    <h1>Security Scan Report</h1>\n");
        sb.append("    <p>Target: ").append(result.getTargetUrl()).append("</p>\n");
        sb.append("    <p>Date: ").append(result.getScanDate()).append("</p>\n");
        sb.append("    <p>Duration: ").append(result.getScanDurationMs() / 1000).append(" seconds</p>\n");
        sb.append("    <h2>Summary</h2>\n");
        sb.append("    <ul>\n");
        sb.append("      <li>High Risk Alerts: ").append(result.getHighAlerts()).append("</li>\n");
        sb.append("      <li>Medium Risk Alerts: ").append(result.getMediumAlerts()).append("</li>\n");
        sb.append("      <li>Low Risk Alerts: ").append(result.getLowAlerts()).append("</li>\n");
        sb.append("      <li>Informational Alerts: ").append(result.getInfoAlerts()).append("</li>\n");
        sb.append("      <li>Total Alerts: ").append(result.getTotalAlerts()).append("</li>\n");
        sb.append("    </ul>\n");
        sb.append("  </div>\n");
        
        // Alerts
        sb.append("  <div class=\"alerts\">\n");
        sb.append("    <h2>Alerts</h2>\n");
        
        for (Alert alert : result.getAlerts()) {
            String severityClass = "";
            
            switch (alert.getSeverity()) {
                case HIGH:
                    severityClass = "high";
                    break;
                case MEDIUM:
                    severityClass = "medium";
                    break;
                case LOW:
                    severityClass = "low";
                    break;
                case INFORMATIONAL:
                    severityClass = "info";
                    break;
            }
            
            sb.append("    <div class=\"alert ").append(severityClass).append("\">\n");
            sb.append("      <h3>").append(alert.getName()).append(" (").append(alert.getSeverity()).append(")</h3>\n");
            
            if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                sb.append("      <p>URL: ").append(alert.getUrl()).append("</p>\n");
            }
            
            if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                sb.append("      <p>Parameter: ").append(alert.getParam()).append("</p>\n");
            }
            
            if (alert.getDescription() != null && !alert.getDescription().isEmpty()) {
                sb.append("      <p>Description: ").append(alert.getDescription()).append("</p>\n");
            }
            
            if (alert.getSolution() != null && !alert.getSolution().isEmpty()) {
                sb.append("      <p>Solution: ").append(alert.getSolution()).append("</p>\n");
            }
            
            sb.append("    </div>\n");
        }
        
        sb.append("  </div>\n");
        sb.append("</body>\n");
        sb.append("</html>");
        
        return sb.toString();
    }
    
    /**
     * Generates an XML report from a scan result.
     * 
     * @param result The scan result
     * @return The XML report
     */
    private String generateXmlReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<report>\n");
        
        // Summary
        sb.append("  <summary>\n");
        sb.append("    <target>").append(result.getTargetUrl()).append("</target>\n");
        sb.append("    <date>").append(result.getScanDate()).append("</date>\n");
        sb.append("    <duration>").append(result.getScanDurationMs()).append("</duration>\n");
        sb.append("    <alerts>\n");
        sb.append("      <high>").append(result.getHighAlerts()).append("</high>\n");
        sb.append("      <medium>").append(result.getMediumAlerts()).append("</medium>\n");
        sb.append("      <low>").append(result.getLowAlerts()).append("</low>\n");
        sb.append("      <info>").append(result.getInfoAlerts()).append("</info>\n");
        sb.append("      <total>").append(result.getTotalAlerts()).append("</total>\n");
        sb.append("    </alerts>\n");
        sb.append("  </summary>\n");
        
        // Alerts
        sb.append("  <alerts>\n");
        
        for (Alert alert : result.getAlerts()) {
            sb.append("    <alert>\n");
            sb.append("      <name>").append(alert.getName()).append("</name>\n");
            sb.append("      <severity>").append(alert.getSeverity()).append("</severity>\n");
            
            if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                sb.append("      <url>").append(alert.getUrl()).append("</url>\n");
            }
            
            if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                sb.append("      <param>").append(alert.getParam()).append("</param>\n");
            }
            
            if (alert.getDescription() != null && !alert.getDescription().isEmpty()) {
                sb.append("      <description>").append(alert.getDescription()).append("</description>\n");
            }
            
            if (alert.getSolution() != null && !alert.getSolution().isEmpty()) {
                sb.append("      <solution>").append(alert.getSolution()).append("</solution>\n");
            }
            
            sb.append("    </alert>\n");
        }
        
        sb.append("  </alerts>\n");
        sb.append("</report>");
        
        return sb.toString();
    }
    
    /**
     * Generates a JSON report from a scan result.
     * 
     * @param result The scan result
     * @return The JSON report
     */
    private String generateJsonReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("{\n");
        sb.append("  \"summary\": {\n");
        sb.append("    \"target\": \"").append(result.getTargetUrl()).append("\",\n");
        sb.append("    \"date\": \"").append(result.getScanDate()).append("\",\n");
        sb.append("    \"duration\": ").append(result.getScanDurationMs()).append(",\n");
        sb.append("    \"alerts\": {\n");
        sb.append("      \"high\": ").append(result.getHighAlerts()).append(",\n");
        sb.append("      \"medium\": ").append(result.getMediumAlerts()).append(",\n");
        sb.append("      \"low\": ").append(result.getLowAlerts()).append(",\n");
        sb.append("      \"info\": ").append(result.getInfoAlerts()).append(",\n");
        sb.append("      \"total\": ").append(result.getTotalAlerts()).append("\n");
        sb.append("    }\n");
        sb.append("  },\n");
        sb.append("  \"alerts\": [\n");
        
        // Alerts
        for (int i = 0; i < result.getAlerts().size(); i++) {
            Alert alert = result.getAlerts().get(i);
            
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(alert.getName()).append("\",\n");
            sb.append("      \"severity\": \"").append(alert.getSeverity()).append("\"");
            
            if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                sb.append(",\n      \"url\": \"").append(alert.getUrl()).append("\"");
            }
            
            if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                sb.append(",\n      \"param\": \"").append(alert.getParam()).append("\"");
            }
            
            if (alert.getDescription() != null && !alert.getDescription().isEmpty()) {
                sb.append(",\n      \"description\": \"").append(alert.getDescription()).append("\"");
            }
            
            if (alert.getSolution() != null && !alert.getSolution().isEmpty()) {
                sb.append(",\n      \"solution\": \"").append(alert.getSolution()).append("\"");
            }
            
            sb.append("\n    }");
            
            if (i < result.getAlerts().size() - 1) {
                sb.append(",");
            }
            
            sb.append("\n");
        }
        
        sb.append("  ]\n");
        sb.append("}");
        
        return sb.toString();
    }
    
    /**
     * Generates a PDF report from a scan result.
     * 
     * @param result The scan result
     * @return The PDF report
     */
    private String generatePdfReport(ScanResult result) {
        // In a real implementation, we would generate a PDF
        // For this stub, we'll return a message
        return "PDF report generation is not implemented in this stub.";
    }
    
    /**
     * Generates a Markdown report from a scan result.
     * 
     * @param result The scan result
     * @return The Markdown report
     */
    private String generateMarkdownReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("# Security Scan Report\n\n");
        
        // Summary
        sb.append("## Summary\n\n");
        sb.append("- Target: ").append(result.getTargetUrl()).append("\n");
        sb.append("- Date: ").append(result.getScanDate()).append("\n");
        sb.append("- Duration: ").append(result.getScanDurationMs() / 1000).append(" seconds\n\n");
        
        sb.append("### Alerts\n\n");
        sb.append("- High Risk Alerts: ").append(result.getHighAlerts()).append("\n");
        sb.append("- Medium Risk Alerts: ").append(result.getMediumAlerts()).append("\n");
        sb.append("- Low Risk Alerts: ").append(result.getLowAlerts()).append("\n");
        sb.append("- Informational Alerts: ").append(result.getInfoAlerts()).append("\n");
        sb.append("- Total Alerts: ").append(result.getTotalAlerts()).append("\n\n");
        
        // Alerts
        sb.append("## Alerts\n\n");
        
        for (Alert alert : result.getAlerts()) {
            sb.append("### ").append(alert.getName()).append(" (").append(alert.getSeverity()).append(")\n\n");
            
            if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                sb.append("- URL: ").append(alert.getUrl()).append("\n");
            }
            
            if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                sb.append("- Parameter: ").append(alert.getParam()).append("\n");
            }
            
            if (alert.getDescription() != null && !alert.getDescription().isEmpty()) {
                sb.append("- Description: ").append(alert.getDescription()).append("\n");
            }
            
            if (alert.getSolution() != null && !alert.getSolution().isEmpty()) {
                sb.append("- Solution: ").append(alert.getSolution()).append("\n");
            }
            
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Writes a report to a file.
     * 
     * @param reportData The report data
     * @param outputPath The output path
     * @throws IOException If writing fails
     */
    private void writeReportToFile(String reportData, String outputPath) throws IOException {
        // Create parent directories if they don't exist
        File outputFile = new File(outputPath);
        if (!outputFile.getParentFile().exists()) {
            outputFile.getParentFile().mkdirs();
        }
        
        // Write the report to the file
        Files.write(Paths.get(outputPath), reportData.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
