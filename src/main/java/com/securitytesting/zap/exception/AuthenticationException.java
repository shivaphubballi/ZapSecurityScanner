package com.securitytesting.zap.exception;

/**
 * Exception thrown for errors that occur during authentication setup or execution.
 */
public class AuthenticationException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new AuthenticationException with the specified detail message.
     * 
     * @param message The detail message
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new AuthenticationException with the specified detail message and cause.
     * 
     * @param message The detail message
     * @param cause The cause
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new AuthenticationException with the specified cause.
     * 
     * @param cause The cause
     */
    public AuthenticationException(Throwable cause) {
        super(cause);
    }
}
