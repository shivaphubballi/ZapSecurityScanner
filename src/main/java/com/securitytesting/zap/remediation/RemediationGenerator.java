package com.securitytesting.zap.remediation;

import com.securitytesting.zap.report.Alert;
import com.securitytesting.zap.report.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates remediation suggestions for detected vulnerabilities.
 * Maps alerts to appropriate remediation guidance.
 */
public class RemediationGenerator {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RemediationGenerator.class);
    
    // Predefined remediation templates by vulnerability type
    private final Map<String, RemediationTemplate> remediationTemplates;
    
    /**
     * Creates a new remediation generator with predefined remediation templates.
     */
    public RemediationGenerator() {
        this.remediationTemplates = new HashMap<>();
        initializeRemediationTemplates();
    }
    
    /**
     * Initializes predefined remediation templates for common vulnerabilities.
     */
    private void initializeRemediationTemplates() {
        // Cross-Site Scripting (XSS)
        remediationTemplates.put("Cross Site Scripting", new RemediationTemplate(
            "Preventing Cross-Site Scripting (XSS)",
            "Cross-Site Scripting (XSS) attacks occur when an attacker is able to inject malicious scripts into web applications that are then executed in users' browsers.",
            List.of(
                "Validate all input data from users and external sources",
                "Use context-appropriate encoding for data outputted in HTML, JavaScript, CSS, or URL contexts",
                "Implement a Content Security Policy (CSP) to restrict script sources",
                "Apply the principle of least privilege by using security attributes like 'httpOnly' and 'secure' for cookies",
                "Consider using modern frameworks which automatically handle XSS protection"
            ),
            List.of(
                "// Example: Output encoding in Java\nimport org.owasp.encoder.Encode;\n\nString userInput = request.getParameter(\"input\");\nString safeOutput = Encode.forHtml(userInput);",
                "// Example: Content Security Policy header\nresponse.setHeader(\"Content-Security-Policy\", \"default-src 'self'; script-src 'self' https://trusted-cdn.com\");"
            ),
            List.of(
                "OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "OWASP Encoder Project: https://owasp.org/www-project-java-encoder/",
                "Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            ),
            "MODERATE",
            60,
            false,
            null
        ));
        
        // SQL Injection
        remediationTemplates.put("SQL Injection", new RemediationTemplate(
            "Preventing SQL Injection",
            "SQL Injection attacks occur when untrusted data is sent to an interpreter as part of a command or query, tricking the interpreter into executing unintended commands or accessing data without authorization.",
            List.of(
                "Use parameterized queries (prepared statements) for all database operations",
                "Apply input validation with allowlisting approaches for user inputs",
                "Use stored procedures with parameterized inputs",
                "Apply the principle of least privilege for database accounts",
                "Implement a Web Application Firewall (WAF) as an additional layer of protection"
            ),
            List.of(
                "// Example: Parameterized query in Java with JDBC\nString query = \"SELECT * FROM users WHERE username = ? AND password = ?\";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, username);\npstmt.setString(2, password);\nResultSet results = pstmt.executeQuery();",
                "// Example: Using an ORM (Hibernate)\nQuery query = session.createQuery(\"from User where username = :username\");\nquery.setParameter(\"username\", username);\nList<User> users = query.list();"
            ),
            List.of(
                "OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "Bobby Tables: A guide to preventing SQL injection: https://bobby-tables.com/"
            ),
            "MODERATE",
            45,
            false,
            null
        ));
        
        // Insecure Direct Object References (IDOR)
        remediationTemplates.put("Insecure Direct Object Reference", new RemediationTemplate(
            "Fixing Insecure Direct Object References (IDOR)",
            "Insecure Direct Object References occur when an application exposes a reference to an internal implementation object, such as a file, directory, database record, or key, without sufficient access control checks.",
            List.of(
                "Use indirect references that are mapped on the server side to actual implementation objects",
                "Implement proper access control checks before each access to a direct object reference",
                "Verify that the user has authorization to access the requested object",
                "Use request parameters that can only be guessed with proper authorization",
                "Avoid exposing direct references to database keys or file paths in URLs"
            ),
            List.of(
                "// Example: Indirect reference mapping in Java\n// Instead of exposing database IDs directly\npublic Map<String, Integer> userTokenMap = new HashMap<>();\n\n// Generate a secure random token for the user\nString token = generateSecureRandomToken();\nuserTokenMap.put(token, userId);\n\n// Later, when retrieving the user\nInteger userId = userTokenMap.get(requestToken);\nif (userId != null && hasAccess(currentUser, userId)) {\n    // Process the request\n}"
            ),
            List.of(
                "OWASP IDOR Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
            ),
            "MODERATE",
            90,
            false,
            null
        ));
        
        // Cross-Site Request Forgery (CSRF)
        remediationTemplates.put("Cross Site Request Forgery", new RemediationTemplate(
            "Preventing Cross-Site Request Forgery (CSRF)",
            "Cross-Site Request Forgery (CSRF) attacks occur when a malicious website tricks a user's browser into making an unwanted action on a site where they're already authenticated.",
            List.of(
                "Implement anti-CSRF tokens in forms and AJAX requests",
                "Verify the origin and referrer headers for sensitive actions",
                "Use the SameSite cookie attribute to restrict cookie transmission",
                "Implement proper CORS policy to restrict cross-origin requests",
                "For APIs, require custom request headers that simple requests cannot set"
            ),
            List.of(
                "// Example: CSRF token in a form\n<form action=\"/transfer\" method=\"post\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"randomToken123\">\n  <input type=\"text\" name=\"amount\">\n  <input type=\"submit\" value=\"Transfer\">\n</form>",
                "// Example: Validating CSRF token in Java\nString formToken = request.getParameter(\"csrf_token\");\nString sessionToken = (String) session.getAttribute(\"csrf_token\");\nif (sessionToken == null || !sessionToken.equals(formToken)) {\n    // Invalid token, reject the request\n    response.sendError(HttpServletResponse.SC_FORBIDDEN);\n    return;\n}"
            ),
            List.of(
                "OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                "SameSite Cookies Explained: https://web.dev/samesite-cookies-explained/"
            ),
            "EASY",
            30,
            false,
            null
        ));
        
        // Server Misconfiguration
        remediationTemplates.put("Server Misconfiguration", new RemediationTemplate(
            "Fixing Server Misconfiguration",
            "Server misconfiguration vulnerabilities occur when security controls are incorrectly configured or left at their insecure default settings.",
            List.of(
                "Remove default or sample content from production servers",
                "Disable directory listings to prevent information disclosure",
                "Implement proper error handling to avoid exposing sensitive information",
                "Enable security headers like X-Content-Type-Options, X-Frame-Options",
                "Configure proper TLS/SSL settings with strong cipher suites",
                "Apply the principle of least privilege for service accounts and users"
            ),
            List.of(
                "# Example: Apache security headers configuration\n<IfModule mod_headers.c>\n  Header set X-Content-Type-Options \"nosniff\"\n  Header set X-Frame-Options \"SAMEORIGIN\"\n  Header set X-XSS-Protection \"1; mode=block\"\n  Header set Content-Security-Policy \"default-src 'self'\"\n</IfModule>",
                "# Example: Disabling directory listing in Apache\n<Directory /var/www/html>\n  Options -Indexes\n</Directory>"
            ),
            List.of(
                "OWASP Top 10 Security Misconfiguration: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                "Mozilla Web Security Guidelines: https://infosec.mozilla.org/guidelines/web_security"
            ),
            "EASY",
            45,
            true,
            "#!/bin/bash\n\n# This script helps secure Apache configurations\n\necho \"Disabling directory listing...\"\necho \"<Directory /var/www/html>\" >> /etc/apache2/conf-available/security.conf\necho \"    Options -Indexes\" >> /etc/apache2/conf-available/security.conf\necho \"</Directory>\" >> /etc/apache2/conf-available/security.conf\n\necho \"Adding security headers...\"\necho \"<IfModule mod_headers.c>\" >> /etc/apache2/conf-available/security.conf\necho \"    Header set X-Content-Type-Options \\\"nosniff\\\"\" >> /etc/apache2/conf-available/security.conf\necho \"    Header set X-Frame-Options \\\"SAMEORIGIN\\\"\" >> /etc/apache2/conf-available/security.conf\necho \"    Header set X-XSS-Protection \\\"1; mode=block\\\"\" >> /etc/apache2/conf-available/security.conf\necho \"</IfModule>\" >> /etc/apache2/conf-available/security.conf\n\necho \"Restarting Apache...\"\napachectl configtest && systemctl restart apache2\n\necho \"Configuration complete!\""
        ));
        
        // Add more templates for other common vulnerabilities
        remediationTemplates.put("Sensitive Data Exposure", new RemediationTemplate(
            "Protecting Sensitive Data",
            "Sensitive data exposure occurs when an application doesn't adequately protect sensitive information, allowing attackers to steal or modify such data.",
            List.of(
                "Identify and classify all sensitive data handled by the application",
                "Implement proper encryption for data at rest and in transit",
                "Use strong, up-to-date algorithms and protocols (e.g., AES-256, TLS 1.3)",
                "Avoid storing sensitive data unnecessarily; minimize data retention",
                "Apply proper key management practices",
                "Implement secure HTTP headers and cookie attributes"
            ),
            List.of(
                "// Example: Setting secure cookie attributes in Java\nCookie cookie = new Cookie(\"session\", sessionId);\ncookie.setHttpOnly(true);\ncookie.setSecure(true); // Only transmitted over HTTPS\nresponse.addCookie(cookie);",
                "// Example: Encrypting sensitive data with AES in Java\nimport javax.crypto.Cipher;\nimport javax.crypto.spec.SecretKeySpec;\n\nbyte[] key = getEncryptionKey(); // Get from secure key management system\nSecretKeySpec secretKey = new SecretKeySpec(key, \"AES\");\nCipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\ncipher.init(Cipher.ENCRYPT_MODE, secretKey);\nbyte[] encryptedData = cipher.doFinal(sensitiveData.getBytes());"
            ),
            List.of(
                "OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                "OWASP Transport Layer Protection Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
            ),
            "COMPLEX",
            120,
            false,
            null
        ));
    }
    
    /**
     * Generates remediation suggestions for all alerts in a scan result.
     *
     * @param scanResult The scan result containing alerts
     * @return A list of remediation suggestions
     */
    public List<RemediationSuggestion> generateRemediation(ScanResult scanResult) {
        LOGGER.info("Generating remediation suggestions for {} alerts", scanResult.getTotalAlerts());
        
        List<RemediationSuggestion> suggestions = new ArrayList<>();
        Map<String, List<Alert>> alertsByType = groupAlertsByType(scanResult.getAlerts());
        
        for (Map.Entry<String, List<Alert>> entry : alertsByType.entrySet()) {
            String alertType = entry.getKey();
            List<Alert> alerts = entry.getValue();
            
            RemediationSuggestion suggestion = generateRemediationForAlertType(alertType, alerts);
            if (suggestion != null) {
                suggestions.add(suggestion);
            }
        }
        
        LOGGER.info("Generated {} remediation suggestions", suggestions.size());
        return suggestions;
    }
    
    /**
     * Groups alerts by their type (name).
     *
     * @param alerts The list of alerts
     * @return A map of alert types to lists of alerts
     */
    private Map<String, List<Alert>> groupAlertsByType(List<Alert> alerts) {
        Map<String, List<Alert>> alertsByType = new HashMap<>();
        
        for (Alert alert : alerts) {
            String alertType = alert.getName();
            alertsByType.computeIfAbsent(alertType, k -> new ArrayList<>()).add(alert);
        }
        
        return alertsByType;
    }
    
    /**
     * Generates a remediation suggestion for a specific alert type.
     *
     * @param alertType The alert type
     * @param alerts The alerts of this type
     * @return A remediation suggestion, or null if no template is available
     */
    private RemediationSuggestion generateRemediationForAlertType(String alertType, List<Alert> alerts) {
        // First, try exact match
        RemediationTemplate template = remediationTemplates.get(alertType);
        
        // If no exact match, try looking for partial matches
        if (template == null) {
            for (Map.Entry<String, RemediationTemplate> entry : remediationTemplates.entrySet()) {
                if (alertType.contains(entry.getKey()) || entry.getKey().contains(alertType)) {
                    template = entry.getValue();
                    break;
                }
            }
        }
        
        // If still no match, use a generic template
        if (template == null) {
            return createGenericRemediationSuggestion(alertType, alerts);
        }
        
        // Build the remediation suggestion from the template
        RemediationSuggestion.Builder builder = new RemediationSuggestion.Builder(template.getTitle())
            .description(template.getDescription() + "\n\nThis issue was detected in " + alerts.size() + " location(s).")
            .steps(template.getSteps())
            .codeExamples(template.getCodeExamples())
            .references(template.getReferences())
            .difficulty(template.getDifficulty())
            .estimatedTimeInMinutes(template.getEstimatedTimeInMinutes());
        
        if (template.isAutomatedFixAvailable()) {
            builder.automatedFixScript(template.getAutomatedFixScript());
        }
        
        return builder.build();
    }
    
    /**
     * Creates a generic remediation suggestion for an alert type without a template.
     *
     * @param alertType The alert type
     * @param alerts The alerts of this type
     * @return A generic remediation suggestion
     */
    private RemediationSuggestion createGenericRemediationSuggestion(String alertType, List<Alert> alerts) {
        LOGGER.info("Creating generic remediation suggestion for alert type: {}", alertType);
        
        // Get the first alert to extract information
        Alert firstAlert = alerts.get(0);
        
        RemediationSuggestion.Builder builder = new RemediationSuggestion.Builder("Remediation for " + alertType)
            .description("This is a generic remediation suggestion for " + alertType + 
                         " vulnerability. This issue was detected in " + alerts.size() + " location(s).");
        
        // Add steps based on the solution from the alert if available
        if (firstAlert.getSolution() != null && !firstAlert.getSolution().isEmpty()) {
            builder.addStep("Review the solution provided by the scanner: " + firstAlert.getSolution());
        } else {
            builder.addStep("Research this vulnerability type to understand its impact and remediation options");
            builder.addStep("Review the affected code or configuration to identify the root cause");
            builder.addStep("Apply appropriate security controls based on best practices");
            builder.addStep("Test the changes to ensure the vulnerability is fixed");
        }
        
        // Add reference to OWASP
        builder.addReference("OWASP Top 10: https://owasp.org/www-project-top-ten/");
        
        // Set difficulty based on severity
        switch (firstAlert.getSeverity()) {
            case HIGH:
                builder.difficulty("COMPLEX").estimatedTimeInMinutes(120);
                break;
            case MEDIUM:
                builder.difficulty("MODERATE").estimatedTimeInMinutes(60);
                break;
            default:
                builder.difficulty("EASY").estimatedTimeInMinutes(30);
                break;
        }
        
        return builder.build();
    }
    
    /**
     * Inner class representing a remediation template.
     */
    private static class RemediationTemplate {
        private final String title;
        private final String description;
        private final List<String> steps;
        private final List<String> codeExamples;
        private final List<String> references;
        private final String difficulty;
        private final int estimatedTimeInMinutes;
        private final boolean automatedFixAvailable;
        private final String automatedFixScript;
        
        /**
         * Creates a new remediation template.
         */
        public RemediationTemplate(
                String title,
                String description,
                List<String> steps,
                List<String> codeExamples,
                List<String> references,
                String difficulty,
                int estimatedTimeInMinutes,
                boolean automatedFixAvailable,
                String automatedFixScript) {
            this.title = title;
            this.description = description;
            this.steps = steps;
            this.codeExamples = codeExamples;
            this.references = references;
            this.difficulty = difficulty;
            this.estimatedTimeInMinutes = estimatedTimeInMinutes;
            this.automatedFixAvailable = automatedFixAvailable;
            this.automatedFixScript = automatedFixScript;
        }
        
        public String getTitle() {
            return title;
        }
        
        public String getDescription() {
            return description;
        }
        
        public List<String> getSteps() {
            return steps;
        }
        
        public List<String> getCodeExamples() {
            return codeExamples;
        }
        
        public List<String> getReferences() {
            return references;
        }
        
        public String getDifficulty() {
            return difficulty;
        }
        
        public int getEstimatedTimeInMinutes() {
            return estimatedTimeInMinutes;
        }
        
        public boolean isAutomatedFixAvailable() {
            return automatedFixAvailable;
        }
        
        public String getAutomatedFixScript() {
            return automatedFixScript;
        }
    }
}
