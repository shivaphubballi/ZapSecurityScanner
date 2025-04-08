package com.securitytesting.zap.report;

/**
 * Enum representing the severity levels of security alerts.
 */
public enum Severity {
    /**
     * High severity alerts represent critical security issues that must be addressed immediately.
     */
    HIGH,
    
    /**
     * Medium severity alerts represent significant security issues that should be addressed soon.
     */
    MEDIUM,
    
    /**
     * Low severity alerts represent minor security issues that should be addressed when possible.
     */
    LOW,
    
    /**
     * Informational alerts represent potential security issues or best practices.
     */
    INFORMATIONAL;
    
    /**
     * Converts a string severity value to a Severity enum.
     * 
     * @param value The string severity value (case-insensitive)
     * @return The corresponding Severity enum, or INFORMATIONAL if not recognized
     */
    public static Severity fromString(String value) {
        if (value == null || value.isEmpty()) {
            return INFORMATIONAL;
        }
        
        switch (value.toUpperCase()) {
            case "HIGH":
                return HIGH;
            case "MEDIUM":
                return MEDIUM;
            case "LOW":
                return LOW;
            case "INFORMATIONAL":
            case "INFO":
                return INFORMATIONAL;
            default:
                return INFORMATIONAL;
        }
    }
    
    /**
     * Converts an integer severity value to a Severity enum.
     * 
     * @param value The integer severity value (3 = HIGH, 2 = MEDIUM, 1 = LOW, 0 = INFORMATIONAL)
     * @return The corresponding Severity enum, or INFORMATIONAL if not recognized
     */
    public static Severity fromValue(int value) {
        switch (value) {
            case 3:
                return HIGH;
            case 2:
                return MEDIUM;
            case 1:
                return LOW;
            case 0:
                return INFORMATIONAL;
            default:
                return INFORMATIONAL;
        }
    }
    
    /**
     * Converts the Severity enum to an integer value.
     * 
     * @return The integer value (3 = HIGH, 2 = MEDIUM, 1 = LOW, 0 = INFORMATIONAL)
     */
    public int getValue() {
        switch (this) {
            case HIGH:
                return 3;
            case MEDIUM:
                return 2;
            case LOW:
                return 1;
            case INFORMATIONAL:
                return 0;
            default:
                return 0;
        }
    }
    
    /**
     * Returns a human-readable string representation of the severity.
     * 
     * @return A human-readable string representation of the severity
     */
    @Override
    public String toString() {
        switch (this) {
            case HIGH:
                return "High";
            case MEDIUM:
                return "Medium";
            case LOW:
                return "Low";
            case INFORMATIONAL:
                return "Informational";
            default:
                return "Unknown";
        }
    }
}
