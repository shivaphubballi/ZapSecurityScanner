package com.securitytesting.zap.exception;

/**
 * Exception thrown for errors that occur during ZAP scanning operations.
 */
public class ZapScannerException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new ZapScannerException with the specified detail message.
     * 
     * @param message The detail message
     */
    public ZapScannerException(String message) {
        super(message);
    }

    /**
     * Constructs a new ZapScannerException with the specified detail message and cause.
     * 
     * @param message The detail message
     * @param cause The cause
     */
    public ZapScannerException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new ZapScannerException with the specified cause.
     * 
     * @param cause The cause
     */
    public ZapScannerException(Throwable cause) {
        super(cause);
    }
}
