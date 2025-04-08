package com.securitytesting.zap.report;

import com.securitytesting.zap.remediation.RemediationGenerator;
import com.securitytesting.zap.remediation.RemediationSuggestion;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates a detailed security report with remediation suggestions.
 * Extends the standard scan report with guided remediation information.
 */
public class RemediationReport {
    
    private final ScanResult scanResult;
    private final List<RemediationSuggestion> remediationSuggestions;
    
    /**
     * Creates a new remediation report from a scan result.
     *
     * @param scanResult The scan result
     */
    public RemediationReport(ScanResult scanResult) {
        this.scanResult = scanResult;
        
        // Generate remediation suggestions
        RemediationGenerator generator = new RemediationGenerator();
        this.remediationSuggestions = generator.generateRemediation(scanResult);
    }
    
    /**
     * Gets the scan result.
     *
     * @return The scan result
     */
    public ScanResult getScanResult() {
        return scanResult;
    }
    
    /**
     * Gets the remediation suggestions.
     *
     * @return The remediation suggestions
     */
    public List<RemediationSuggestion> getRemediationSuggestions() {
        return remediationSuggestions;
    }
    
    /**
     * Generates a Markdown report with remediation suggestions.
     *
     * @return The Markdown report
     */
    public String generateMarkdownReport() {
        StringBuilder sb = new StringBuilder();
        
        // Report header
        sb.append("# Security Scan Report with Remediation Guidance\n\n");
        sb.append("**Target:** ").append(scanResult.getTargetUrl()).append("\n\n");
        sb.append("**Date:** ").append(scanResult.getScanDate()).append("\n\n");
        sb.append("**Scan Duration:** ").append(scanResult.getScanDurationMs() / 1000).append(" seconds\n\n");
        
        // Alert summary
        sb.append("## Summary of Findings\n\n");
        sb.append("| Severity | Count |\n");
        sb.append("|----------|-------|\n");
        sb.append("| High | ").append(scanResult.getHighAlerts()).append(" |\n");
        sb.append("| Medium | ").append(scanResult.getMediumAlerts()).append(" |\n");
        sb.append("| Low | ").append(scanResult.getLowAlerts()).append(" |\n");
        sb.append("| Informational | ").append(scanResult.getInfoAlerts()).append(" |\n");
        sb.append("| **Total** | **").append(scanResult.getTotalAlerts()).append("** |\n\n");
        
        // Group alerts by type
        Map<String, List<Alert>> alertsByType = scanResult.getAlerts().stream()
                .collect(Collectors.groupingBy(Alert::getName));
        
        // Alert details
        sb.append("## Detected Vulnerabilities\n\n");
        
        for (Map.Entry<String, List<Alert>> entry : alertsByType.entrySet()) {
            String alertType = entry.getKey();
            List<Alert> alerts = entry.getValue();
            
            sb.append("### ").append(alertType).append(" (").append(alerts.size()).append(" instance(s))\n\n");
            
            // Display first alert details as an example
            Alert firstAlert = alerts.get(0);
            sb.append("**Severity:** ").append(firstAlert.getSeverity()).append("\n\n");
            
            if (firstAlert.getDescription() != null && !firstAlert.getDescription().isEmpty()) {
                sb.append("**Description:** ").append(firstAlert.getDescription()).append("\n\n");
            }
            
            // List affected URLs
            sb.append("**Affected URLs:**\n\n");
            for (Alert alert : alerts) {
                if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                    sb.append("- ").append(alert.getUrl());
                    
                    if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                        sb.append(" (Parameter: ").append(alert.getParam()).append(")");
                    }
                    
                    sb.append("\n");
                }
            }
            sb.append("\n");
        }
        
        // Remediation guidance
        sb.append("## Remediation Guidance\n\n");
        
        if (remediationSuggestions.isEmpty()) {
            sb.append("No specific remediation suggestions available for the detected vulnerabilities.\n\n");
        } else {
            for (RemediationSuggestion suggestion : remediationSuggestions) {
                sb.append(suggestion.toFormattedText()).append("\n\n");
                sb.append("---\n\n");
            }
        }
        
        // Best practices
        sb.append("## General Security Best Practices\n\n");
        sb.append("1. **Keep software updated** - Regularly update frameworks, libraries, and dependencies\n");
        sb.append("2. **Implement security headers** - Use security headers like CSP, X-Content-Type-Options, etc.\n");
        sb.append("3. **Apply principle of least privilege** - Restrict access rights to the minimum necessary\n");
        sb.append("4. **Conduct regular security testing** - Perform security testing throughout the development lifecycle\n");
        sb.append("5. **Implement secure coding practices** - Train developers on secure coding guidelines\n");
        sb.append("6. **Monitor for vulnerabilities** - Use tools to identify vulnerabilities in dependencies\n\n");
        
        sb.append("## References\n\n");
        sb.append("- [OWASP Top 10](https://owasp.org/www-project-top-ten/)\n");
        sb.append("- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)\n");
        sb.append("- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)\n");
        
        return sb.toString();
    }
    
    /**
     * Generates an HTML report with remediation suggestions.
     *
     * @return The HTML report
     */
    public String generateHtmlReport() {
        StringBuilder sb = new StringBuilder();
        
        // HTML header
        sb.append("<!DOCTYPE html>\n<html>\n<head>\n");
        sb.append("  <title>Security Scan Report with Remediation Guidance</title>\n");
        sb.append("  <style>\n");
        sb.append("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }\n");
        sb.append("    h1, h2, h3 { color: #2c3e50; }\n");
        sb.append("    .summary { margin-bottom: 30px; }\n");
        sb.append("    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n");
        sb.append("    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        sb.append("    th { background-color: #f2f2f2; }\n");
        sb.append("    .high { color: #c0392b; }\n");
        sb.append("    .medium { color: #e67e22; }\n");
        sb.append("    .low { color: #2980b9; }\n");
        sb.append("    .info { color: #27ae60; }\n");
        sb.append("    .alert { margin-bottom: 20px; padding: 15px; border-left: 5px solid #ccc; }\n");
        sb.append("    .alert.high { border-left-color: #c0392b; }\n");
        sb.append("    .alert.medium { border-left-color: #e67e22; }\n");
        sb.append("    .alert.low { border-left-color: #2980b9; }\n");
        sb.append("    .alert.info { border-left-color: #27ae60; }\n");
        sb.append("    .remediation { background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; border-radius: 5px; }\n");
        sb.append("    .code { background-color: #f5f5f5; padding: 10px; border-radius: 5px; font-family: monospace; overflow-x: auto; }\n");
        sb.append("    .step { margin-bottom: 10px; }\n");
        sb.append("    .difficulty { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 0.8em; }\n");
        sb.append("    .easy { background-color: #dff0d8; color: #3c763d; }\n");
        sb.append("    .moderate { background-color: #fcf8e3; color: #8a6d3b; }\n");
        sb.append("    .complex { background-color: #f2dede; color: #a94442; }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n<body>\n");
        
        // Report header
        sb.append("  <h1>Security Scan Report with Remediation Guidance</h1>\n");
        sb.append("  <div class=\"summary\">\n");
        sb.append("    <p><strong>Target:</strong> ").append(scanResult.getTargetUrl()).append("</p>\n");
        sb.append("    <p><strong>Date:</strong> ").append(scanResult.getScanDate()).append("</p>\n");
        sb.append("    <p><strong>Scan Duration:</strong> ").append(scanResult.getScanDurationMs() / 1000).append(" seconds</p>\n");
        sb.append("  </div>\n");
        
        // Alert summary
        sb.append("  <h2>Summary of Findings</h2>\n");
        sb.append("  <table>\n");
        sb.append("    <tr><th>Severity</th><th>Count</th></tr>\n");
        sb.append("    <tr><td class=\"high\">High</td><td>").append(scanResult.getHighAlerts()).append("</td></tr>\n");
        sb.append("    <tr><td class=\"medium\">Medium</td><td>").append(scanResult.getMediumAlerts()).append("</td></tr>\n");
        sb.append("    <tr><td class=\"low\">Low</td><td>").append(scanResult.getLowAlerts()).append("</td></tr>\n");
        sb.append("    <tr><td class=\"info\">Informational</td><td>").append(scanResult.getInfoAlerts()).append("</td></tr>\n");
        sb.append("    <tr><th>Total</th><th>").append(scanResult.getTotalAlerts()).append("</th></tr>\n");
        sb.append("  </table>\n");
        
        // Group alerts by type
        Map<String, List<Alert>> alertsByType = scanResult.getAlerts().stream()
                .collect(Collectors.groupingBy(Alert::getName));
        
        // Alert details
        sb.append("  <h2>Detected Vulnerabilities</h2>\n");
        
        for (Map.Entry<String, List<Alert>> entry : alertsByType.entrySet()) {
            String alertType = entry.getKey();
            List<Alert> alerts = entry.getValue();
            
            // Get the severity class for styling
            String severityClass = "info";
            if (!alerts.isEmpty()) {
                switch (alerts.get(0).getSeverity()) {
                    case HIGH:
                        severityClass = "high";
                        break;
                    case MEDIUM:
                        severityClass = "medium";
                        break;
                    case LOW:
                        severityClass = "low";
                        break;
                    default:
                        severityClass = "info";
                        break;
                }
            }
            
            sb.append("  <div class=\"alert ").append(severityClass).append("\">\n");
            sb.append("    <h3>").append(alertType).append(" (").append(alerts.size()).append(" instance(s))</h3>\n");
            
            // Display first alert details as an example
            Alert firstAlert = alerts.get(0);
            sb.append("    <p><strong>Severity:</strong> <span class=\"").append(severityClass).append("\">")
              .append(firstAlert.getSeverity()).append("</span></p>\n");
            
            if (firstAlert.getDescription() != null && !firstAlert.getDescription().isEmpty()) {
                sb.append("    <p><strong>Description:</strong> ").append(firstAlert.getDescription()).append("</p>\n");
            }
            
            // List affected URLs
            sb.append("    <p><strong>Affected URLs:</strong></p>\n");
            sb.append("    <ul>\n");
            for (Alert alert : alerts) {
                if (alert.getUrl() != null && !alert.getUrl().isEmpty()) {
                    sb.append("      <li>").append(alert.getUrl());
                    
                    if (alert.getParam() != null && !alert.getParam().isEmpty()) {
                        sb.append(" (Parameter: ").append(alert.getParam()).append(")");
                    }
                    
                    sb.append("</li>\n");
                }
            }
            sb.append("    </ul>\n");
            sb.append("  </div>\n");
        }
        
        // Remediation guidance
        sb.append("  <h2>Remediation Guidance</h2>\n");
        
        if (remediationSuggestions.isEmpty()) {
            sb.append("  <p>No specific remediation suggestions available for the detected vulnerabilities.</p>\n");
        } else {
            for (RemediationSuggestion suggestion : remediationSuggestions) {
                sb.append("  <div class=\"remediation\">\n");
                sb.append("    <h3>").append(suggestion.getTitle()).append("</h3>\n");
                sb.append("    <p>").append(suggestion.getDescription().replace("\n", "<br>")).append("</p>\n");
                
                // Steps
                sb.append("    <h4>Steps to Fix</h4>\n");
                sb.append("    <ol>\n");
                for (String step : suggestion.getSteps()) {
                    sb.append("      <li class=\"step\">").append(step).append("</li>\n");
                }
                sb.append("    </ol>\n");
                
                // Code examples
                if (!suggestion.getCodeExamples().isEmpty()) {
                    sb.append("    <h4>Code Examples</h4>\n");
                    for (String codeExample : suggestion.getCodeExamples()) {
                        sb.append("    <pre class=\"code\">").append(codeExample.replace("<", "&lt;").replace(">", "&gt;")).append("</pre>\n");
                    }
                }
                
                // Implementation details
                sb.append("    <h4>Implementation Details</h4>\n");
                
                // Difficulty
                String difficultyClass = "moderate";
                if ("EASY".equals(suggestion.getDifficulty())) {
                    difficultyClass = "easy";
                } else if ("COMPLEX".equals(suggestion.getDifficulty())) {
                    difficultyClass = "complex";
                }
                
                sb.append("    <p><strong>Difficulty:</strong> <span class=\"difficulty ").append(difficultyClass).append("\">")
                  .append(suggestion.getDifficulty()).append("</span></p>\n");
                sb.append("    <p><strong>Estimated Time:</strong> ").append(suggestion.getEstimatedTimeInMinutes()).append(" minutes</p>\n");
                sb.append("    <p><strong>Automated Fix Available:</strong> ").append(suggestion.hasAutomatedFix() ? "Yes" : "No").append("</p>\n");
                
                // References
                if (!suggestion.getReferences().isEmpty()) {
                    sb.append("    <h4>References</h4>\n");
                    sb.append("    <ul>\n");
                    for (String reference : suggestion.getReferences()) {
                        sb.append("      <li>").append(reference.replace("https://", "<a href=\"https://").replace(" ", "</a> ")).append("</li>\n");
                    }
                    sb.append("    </ul>\n");
                }
                
                sb.append("  </div>\n");
            }
        }
        
        // Best practices
        sb.append("  <h2>General Security Best Practices</h2>\n");
        sb.append("  <ol>\n");
        sb.append("    <li><strong>Keep software updated</strong> - Regularly update frameworks, libraries, and dependencies</li>\n");
        sb.append("    <li><strong>Implement security headers</strong> - Use security headers like CSP, X-Content-Type-Options, etc.</li>\n");
        sb.append("    <li><strong>Apply principle of least privilege</strong> - Restrict access rights to the minimum necessary</li>\n");
        sb.append("    <li><strong>Conduct regular security testing</strong> - Perform security testing throughout the development lifecycle</li>\n");
        sb.append("    <li><strong>Implement secure coding practices</strong> - Train developers on secure coding guidelines</li>\n");
        sb.append("    <li><strong>Monitor for vulnerabilities</strong> - Use tools to identify vulnerabilities in dependencies</li>\n");
        sb.append("  </ol>\n");
        
        sb.append("  <h2>References</h2>\n");
        sb.append("  <ul>\n");
        sb.append("    <li><a href=\"https://owasp.org/www-project-top-ten/\">OWASP Top 10</a></li>\n");
        sb.append("    <li><a href=\"https://cheatsheetseries.owasp.org/\">OWASP Cheat Sheet Series</a></li>\n");
        sb.append("    <li><a href=\"https://owasp.org/www-project-web-security-testing-guide/\">Web Security Testing Guide</a></li>\n");
        sb.append("  </ul>\n");
        
        // HTML footer
        sb.append("</body>\n</html>");
        
        return sb.toString();
    }
    
    /**
     * Saves the remediation report to a file.
     *
     * @param outputPath The output path
     * @param format The format (HTML or Markdown)
     * @throws IOException If saving fails
     */
    public void saveToFile(String outputPath, String format) throws IOException {
        String reportContent;
        
        if ("html".equalsIgnoreCase(format)) {
            reportContent = generateHtmlReport();
        } else {
            reportContent = generateMarkdownReport();
        }
        
        File outputFile = new File(outputPath);
        
        // Create parent directories if they don't exist
        if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
            outputFile.getParentFile().mkdirs();
        }
        
        // Write the report to the file
        Files.write(Paths.get(outputPath), reportContent.getBytes(), 
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
