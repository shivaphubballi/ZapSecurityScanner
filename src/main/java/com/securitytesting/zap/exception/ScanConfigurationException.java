package com.securitytesting.zap.exception;

/**
 * Exception thrown for errors in scan configuration.
 */
public class ScanConfigurationException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new ScanConfigurationException with the specified detail message.
     * 
     * @param message The detail message
     */
    public ScanConfigurationException(String message) {
        super(message);
    }

    /**
     * Constructs a new ScanConfigurationException with the specified detail message and cause.
     * 
     * @param message The detail message
     * @param cause The cause
     */
    public ScanConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new ScanConfigurationException with the specified cause.
     * 
     * @param cause The cause
     */
    public ScanConfigurationException(Throwable cause) {
        super(cause);
    }
}
