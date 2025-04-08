package com.securitytesting.zap.report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a security alert/finding from a ZAP scan.
 */
public class Alert {
    
    private final int alertId;
    private final String name;
    private final Severity severity;
    private final String description;
    private final String cwe;
    private final String solution;
    private final String reference;
    private final List<String> urls;
    private final Map<String, String> parameters;
    private final Map<String, String> evidence;
    private final boolean confirmed;
    
    private Alert(Builder builder) {
        this.alertId = builder.alertId;
        this.name = builder.name;
        this.severity = builder.severity;
        this.description = builder.description;
        this.cwe = builder.cwe;
        this.solution = builder.solution;
        this.reference = builder.reference;
        this.urls = new ArrayList<>(builder.urls);
        this.parameters = new HashMap<>(builder.parameters);
        this.evidence = new HashMap<>(builder.evidence);
        this.confirmed = builder.confirmed;
    }
    
    /**
     * Gets the alert ID.
     * 
     * @return The alert ID
     */
    public int getAlertId() {
        return alertId;
    }
    
    /**
     * Gets the alert name/title.
     * 
     * @return The alert name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Gets the alert severity.
     * 
     * @return The alert severity
     */
    public Severity getSeverity() {
        return severity;
    }
    
    /**
     * Gets the alert description.
     * 
     * @return The alert description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Gets the CWE (Common Weakness Enumeration) ID.
     * 
     * @return The CWE ID
     */
    public String getCwe() {
        return cwe;
    }
    
    /**
     * Gets the suggested solution.
     * 
     * @return The solution text
     */
    public String getSolution() {
        return solution;
    }
    
    /**
     * Gets reference information for further reading.
     * 
     * @return The reference text
     */
    public String getReference() {
        return reference;
    }
    
    /**
     * Gets the URLs where this alert was found.
     * 
     * @return List of URLs
     */
    public List<String> getUrls() {
        return new ArrayList<>(urls);
    }
    
    /**
     * Gets the parameters associated with this alert.
     * 
     * @return Map of parameter names to values
     */
    public Map<String, String> getParameters() {
        return new HashMap<>(parameters);
    }
    
    /**
     * Gets the evidence that triggered this alert.
     * 
     * @return Map of evidence descriptions to values
     */
    public Map<String, String> getEvidence() {
        return new HashMap<>(evidence);
    }
    
    /**
     * Checks if this alert has been confirmed (not a false positive).
     * 
     * @return true if confirmed, false otherwise
     */
    public boolean isConfirmed() {
        return confirmed;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Alert alert = (Alert) o;
        return alertId == alert.alertId &&
                confirmed == alert.confirmed &&
                Objects.equals(name, alert.name) &&
                severity == alert.severity;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(alertId, name, severity, confirmed);
    }
    
    @Override
    public String toString() {
        return "Alert{" +
                "alertId=" + alertId +
                ", name='" + name + '\'' +
                ", severity=" + severity +
                ", urls=" + urls +
                '}';
    }
    
    /**
     * Builder for creating Alert instances.
     */
    public static class Builder {
        private int alertId;
        private String name;
        private Severity severity = Severity.INFORMATIONAL;
        private String description = "";
        private String cwe = "";
        private String solution = "";
        private String reference = "";
        private final List<String> urls = new ArrayList<>();
        private final Map<String, String> parameters = new HashMap<>();
        private final Map<String, String> evidence = new HashMap<>();
        private boolean confirmed = false;
        
        /**
         * Creates a new builder with the specified alert name.
         * 
         * @param name The alert name
         */
        public Builder(String name) {
            this.name = name;
        }
        
        /**
         * Sets the alert ID.
         * 
         * @param alertId The alert ID
         * @return This builder for method chaining
         */
        public Builder alertId(int alertId) {
            this.alertId = alertId;
            return this;
        }
        
        /**
         * Sets the alert name/title.
         * 
         * @param name The alert name
         * @return This builder for method chaining
         */
        public Builder name(String name) {
            this.name = name;
            return this;
        }
        
        /**
         * Sets the alert severity.
         * 
         * @param severity The alert severity
         * @return This builder for method chaining
         */
        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }
        
        /**
         * Sets the alert description.
         * 
         * @param description The alert description
         * @return This builder for method chaining
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        /**
         * Sets the CWE (Common Weakness Enumeration) ID.
         * 
         * @param cwe The CWE ID
         * @return This builder for method chaining
         */
        public Builder cwe(String cwe) {
            this.cwe = cwe;
            return this;
        }
        
        /**
         * Sets the suggested solution.
         * 
         * @param solution The solution text
         * @return This builder for method chaining
         */
        public Builder solution(String solution) {
            this.solution = solution;
            return this;
        }
        
        /**
         * Sets reference information for further reading.
         * 
         * @param reference The reference text
         * @return This builder for method chaining
         */
        public Builder reference(String reference) {
            this.reference = reference;
            return this;
        }
        
        /**
         * Adds a URL where this alert was found.
         * 
         * @param url The URL
         * @return This builder for method chaining
         */
        public Builder addUrl(String url) {
            if (url != null && !url.isEmpty()) {
                this.urls.add(url);
            }
            return this;
        }
        
        /**
         * Adds a parameter associated with this alert.
         * 
         * @param name The parameter name
         * @param value The parameter value
         * @return This builder for method chaining
         */
        public Builder addParameter(String name, String value) {
            if (name != null && !name.isEmpty()) {
                this.parameters.put(name, value);
            }
            return this;
        }
        
        /**
         * Adds evidence that triggered this alert.
         * 
         * @param description The evidence description
         * @param value The evidence value
         * @return This builder for method chaining
         */
        public Builder addEvidence(String description, String value) {
            if (description != null && !description.isEmpty()) {
                this.evidence.put(description, value);
            }
            return this;
        }
        
        /**
         * Sets whether this alert has been confirmed (not a false positive).
         * 
         * @param confirmed true if confirmed, false otherwise
         * @return This builder for method chaining
         */
        public Builder confirmed(boolean confirmed) {
            this.confirmed = confirmed;
            return this;
        }
        
        /**
         * Builds the alert.
         * 
         * @return A new Alert instance
         */
        public Alert build() {
            return new Alert(this);
        }
    }
}
