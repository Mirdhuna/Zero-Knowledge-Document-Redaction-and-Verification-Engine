package com.zeroknowledge.exception;

/**
 * Exception thrown when document reading, parsing, or format validation fails.
 * Never include raw confidential document content in exception messages.
 */
public class DocumentProcessingException extends Exception {
    private static final long serialVersionUID = 1L;

    public DocumentProcessingException(String message) {
        super(message);
    }

    public DocumentProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}
