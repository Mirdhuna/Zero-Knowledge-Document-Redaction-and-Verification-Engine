package com.zeroknowledge.exception;

/**
 * Exception thrown when redaction execution, offset resolution, or safe file output fails.
 * Never include raw confidential values in exception messages.
 */
public class RedactionException extends Exception {
    private static final long serialVersionUID = 1L;

    public RedactionException(String message) {
        super(message);
    }

    public RedactionException(String message, Throwable cause) {
        super(message, cause);
    }
}
