package com.zeroknowledge.exception;

/**
 * Exception thrown when digital signature generation, loading, or cryptographic verification encounters a severe error.
 */
public class SignatureVerificationException extends Exception {
    private static final long serialVersionUID = 1L;

    public SignatureVerificationException(String message) {
        super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
