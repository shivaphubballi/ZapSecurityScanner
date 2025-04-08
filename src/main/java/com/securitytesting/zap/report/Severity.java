package com.securitytesting.zap.report;

/**
 * Enumeration of severity levels for security vulnerabilities.
 */
public enum Severity {
    
    INFORMATIONAL(0, "Informational", "Informational alerts provide contextual information but don't indicate a security risk."),
    LOW(1, "Low", "Low severity issues present minimal risk to the application."),
    MEDIUM(2, "Medium", "Medium severity issues present moderate risk and should be addressed."),
    HIGH(3, "High", "High severity issues present significant risk and require prompt remediation."),
    CRITICAL(4, "Critical", "Critical issues present severe, immediate risk and demand urgent remediation.");
    
    private final int level;
    private final String name;
    private final String description;
    
    Severity(int level, String name, String description) {
        this.level = level;
        this.name = name;
        this.description = description;
    }
    
    /**
     * Gets the numeric level of this severity.
     * 
     * @return The severity level (higher means more severe)
     */
    public int getLevel() {
        return level;
    }
    
    /**
     * Gets the name of this severity level.
     * 
     * @return The severity name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Gets a description of this severity level.
     * 
     * @return The severity description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Gets a severity enum value from the ZAP API risk index.
     * 
     * @param riskIndex The risk index from ZAP API (0-3)
     * @return The corresponding severity enum value
     */
    public static Severity fromZapRiskIndex(int riskIndex) {
        switch (riskIndex) {
            case 3:
                return HIGH;
            case 2:
                return MEDIUM;
            case 1:
                return LOW;
            case 0:
            default:
                return INFORMATIONAL;
        }
    }
    
    /**
     * Gets a severity enum value from a string representation.
     * 
     * @param severityName The severity name
     * @return The corresponding severity enum value, or INFORMATIONAL if not recognized
     */
    public static Severity fromString(String severityName) {
        if (severityName == null) {
            return INFORMATIONAL;
        }
        
        for (Severity severity : values()) {
            if (severity.name.equalsIgnoreCase(severityName) || 
                severity.name().equalsIgnoreCase(severityName)) {
                return severity;
            }
        }
        
        return INFORMATIONAL;
    }
}
