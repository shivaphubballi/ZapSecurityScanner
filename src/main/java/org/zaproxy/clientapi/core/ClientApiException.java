package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP ClientApiException class.
 */
public class ClientApiException extends Exception {
    public ClientApiException(String message) {
        super(message);
    }
    
    public ClientApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
