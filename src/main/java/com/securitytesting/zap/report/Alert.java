package com.securitytesting.zap.report;

/**
 * Represents a security alert detected during a scan.
 * Contains details about the vulnerability, including severity, description, and location.
 */
public class Alert {
    private String name;
    private String description;
    private String url;
    private String attack;
    private String evidence;
    private String solution;
    private String reference;
    private String param;
    private Severity severity;
    private int cweId;
    private int wascId;
    private String otherInfo;
    
    /**
     * Creates a new alert with the specified name and severity.
     * 
     * @param name The name of the alert
     * @param severity The severity of the alert
     */
    public Alert(String name, Severity severity) {
        this.name = name;
        this.severity = severity;
    }
    
    /**
     * Creates a new alert from a builder.
     * 
     * @param builder The builder
     */
    private Alert(Builder builder) {
        this.name = builder.name;
        this.description = builder.description;
        this.url = builder.url;
        this.attack = builder.attack;
        this.evidence = builder.evidence;
        this.solution = builder.solution;
        this.reference = builder.reference;
        this.param = builder.param;
        this.severity = builder.severity;
        this.cweId = builder.cweId;
        this.wascId = builder.wascId;
        this.otherInfo = builder.otherInfo;
    }
    
    /**
     * Gets the name of the alert.
     * 
     * @return The name of the alert
     */
    public String getName() {
        return name;
    }
    
    /**
     * Sets the name of the alert.
     * 
     * @param name The name of the alert
     */
    public void setName(String name) {
        this.name = name;
    }
    
    /**
     * Gets the description of the alert.
     * 
     * @return The description of the alert
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Sets the description of the alert.
     * 
     * @param description The description of the alert
     */
    public void setDescription(String description) {
        this.description = description;
    }
    
    /**
     * Gets the URL where the alert was detected.
     * 
     * @return The URL
     */
    public String getUrl() {
        return url;
    }
    
    /**
     * Sets the URL where the alert was detected.
     * 
     * @param url The URL
     */
    public void setUrl(String url) {
        this.url = url;
    }
    
    /**
     * Gets the attack that triggered the alert.
     * 
     * @return The attack
     */
    public String getAttack() {
        return attack;
    }
    
    /**
     * Sets the attack that triggered the alert.
     * 
     * @param attack The attack
     */
    public void setAttack(String attack) {
        this.attack = attack;
    }
    
    /**
     * Gets the evidence that triggered the alert.
     * 
     * @return The evidence
     */
    public String getEvidence() {
        return evidence;
    }
    
    /**
     * Sets the evidence that triggered the alert.
     * 
     * @param evidence The evidence
     */
    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }
    
    /**
     * Gets the solution for the alert.
     * 
     * @return The solution
     */
    public String getSolution() {
        return solution;
    }
    
    /**
     * Sets the solution for the alert.
     * 
     * @param solution The solution
     */
    public void setSolution(String solution) {
        this.solution = solution;
    }
    
    /**
     * Gets the reference for the alert.
     * 
     * @return The reference
     */
    public String getReference() {
        return reference;
    }
    
    /**
     * Sets the reference for the alert.
     * 
     * @param reference The reference
     */
    public void setReference(String reference) {
        this.reference = reference;
    }
    
    /**
     * Gets the parameter that triggered the alert.
     * 
     * @return The parameter
     */
    public String getParam() {
        return param;
    }
    
    /**
     * Sets the parameter that triggered the alert.
     * 
     * @param param The parameter
     */
    public void setParam(String param) {
        this.param = param;
    }
    
    /**
     * Gets the severity of the alert.
     * 
     * @return The severity
     */
    public Severity getSeverity() {
        return severity;
    }
    
    /**
     * Sets the severity of the alert.
     * 
     * @param severity The severity
     */
    public void setSeverity(Severity severity) {
        this.severity = severity;
    }
    
    /**
     * Gets the CWE ID of the alert.
     * 
     * @return The CWE ID
     */
    public int getCweId() {
        return cweId;
    }
    
    /**
     * Sets the CWE ID of the alert.
     * 
     * @param cweId The CWE ID
     */
    public void setCweId(int cweId) {
        this.cweId = cweId;
    }
    
    /**
     * Gets the WASC ID of the alert.
     * 
     * @return The WASC ID
     */
    public int getWascId() {
        return wascId;
    }
    
    /**
     * Sets the WASC ID of the alert.
     * 
     * @param wascId The WASC ID
     */
    public void setWascId(int wascId) {
        this.wascId = wascId;
    }
    
    /**
     * Gets additional information about the alert.
     * 
     * @return Additional information
     */
    public String getOtherInfo() {
        return otherInfo;
    }
    
    /**
     * Sets additional information about the alert.
     * 
     * @param otherInfo Additional information
     */
    public void setOtherInfo(String otherInfo) {
        this.otherInfo = otherInfo;
    }
    
    /**
     * Creates a summary of the alert.
     * 
     * @return A summary of the alert
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Alert: ").append(name).append(" (").append(severity).append(")\n");
        
        if (url != null && !url.isEmpty()) {
            sb.append("URL: ").append(url).append("\n");
        }
        
        if (param != null && !param.isEmpty()) {
            sb.append("Parameter: ").append(param).append("\n");
        }
        
        if (description != null && !description.isEmpty()) {
            sb.append("Description: ").append(description).append("\n");
        }
        
        if (solution != null && !solution.isEmpty()) {
            sb.append("Solution: ").append(solution).append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Builder for Alert.
     */
    public static class Builder {
        private final String name;
        private String description;
        private String url;
        private String attack;
        private String evidence;
        private String solution;
        private String reference;
        private String param;
        private Severity severity;
        private int cweId;
        private int wascId;
        private String otherInfo;
        
        /**
         * Creates a new builder with the specified name.
         * 
         * @param name The name of the alert
         */
        public Builder(String name) {
            this.name = name;
            this.severity = Severity.INFORMATIONAL; // Default severity
        }
        
        /**
         * Sets the description of the alert.
         * 
         * @param description The description of the alert
         * @return This builder
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        /**
         * Sets the URL where the alert was detected.
         * 
         * @param url The URL
         * @return This builder
         */
        public Builder url(String url) {
            this.url = url;
            return this;
        }
        
        /**
         * Sets the attack that triggered the alert.
         * 
         * @param attack The attack
         * @return This builder
         */
        public Builder attack(String attack) {
            this.attack = attack;
            return this;
        }
        
        /**
         * Sets the evidence that triggered the alert.
         * 
         * @param evidence The evidence
         * @return This builder
         */
        public Builder evidence(String evidence) {
            this.evidence = evidence;
            return this;
        }
        
        /**
         * Sets the solution for the alert.
         * 
         * @param solution The solution
         * @return This builder
         */
        public Builder solution(String solution) {
            this.solution = solution;
            return this;
        }
        
        /**
         * Sets the reference for the alert.
         * 
         * @param reference The reference
         * @return This builder
         */
        public Builder reference(String reference) {
            this.reference = reference;
            return this;
        }
        
        /**
         * Sets the parameter that triggered the alert.
         * 
         * @param param The parameter
         * @return This builder
         */
        public Builder param(String param) {
            this.param = param;
            return this;
        }
        
        /**
         * Sets the severity of the alert.
         * 
         * @param severity The severity
         * @return This builder
         */
        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }
        
        /**
         * Sets the CWE ID of the alert.
         * 
         * @param cweId The CWE ID
         * @return This builder
         */
        public Builder cweId(int cweId) {
            this.cweId = cweId;
            return this;
        }
        
        /**
         * Sets the WASC ID of the alert.
         * 
         * @param wascId The WASC ID
         * @return This builder
         */
        public Builder wascId(int wascId) {
            this.wascId = wascId;
            return this;
        }
        
        /**
         * Sets additional information about the alert.
         * 
         * @param otherInfo Additional information
         * @return This builder
         */
        public Builder otherInfo(String otherInfo) {
            this.otherInfo = otherInfo;
            return this;
        }
        
        /**
         * Builds the alert.
         * 
         * @return The alert
         */
        public Alert build() {
            return new Alert(this);
        }
    }
}
