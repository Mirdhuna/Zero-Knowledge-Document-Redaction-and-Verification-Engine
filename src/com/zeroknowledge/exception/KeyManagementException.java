package com.zeroknowledge.exception;

/**
 * Exception thrown when RSA key generation, storage, password-based wrapping, or public-key parsing fails.
 * Never expose private key material or passphrases in exception messages.
 */
public class KeyManagementException extends Exception {
    private static final long serialVersionUID = 1L;

    public KeyManagementException(String message) {
        super(message);
    }

    public KeyManagementException(String message, Throwable cause) {
        super(message, cause);
    }
}
