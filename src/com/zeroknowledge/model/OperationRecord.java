package com.zeroknowledge.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Privacy-preserving audit record for an engine operation.
 * Never stores confidential document text, raw PII matches, passphrases, or private key bytes.
 */
public final class OperationRecord {

    public enum OperationType {
        DOCUMENT_SCAN,
        DOCUMENT_REDACT,
        HASH_CALCULATION,
        KEY_GENERATION,
        KEY_LOAD,
        KEY_EXPORT,
        DOCUMENT_SIGN,
        SIGNATURE_VERIFY,
        ACCESS_CHECK,
        UNSUPPORTED_PDF_OPERATION
    }

    private final Instant timestamp;
    private final OperationType operationType;
    private final String documentIdentifier;
    private final boolean success;
    private final String details;

    public OperationRecord(
            Instant timestamp,
            OperationType operationType,
            String documentIdentifier,
            boolean success,
            String details) {
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null");
        this.operationType = Objects.requireNonNull(operationType, "operationType must not be null");
        this.documentIdentifier = documentIdentifier == null ? "N/A" : documentIdentifier;
        this.success = success;
        this.details = details == null ? "" : details;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public String getDocumentIdentifier() {
        return documentIdentifier;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getDetails() {
        return details;
    }

    /**
     * Serializes the audit record into a single sanitized log line.
     */
    public String toLogLine() {
        String safeDoc = sanitize(documentIdentifier);
        String safeDetails = sanitize(details);
        return timestamp.toString()
                + " | OP=" + operationType.name()
                + " | STATUS=" + (success ? "SUCCESS" : "FAILURE")
                + " | TARGET=" + safeDoc
                + " | DETAILS=" + safeDetails;
    }

    private static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        return input.replace('\r', ' ').replace('\n', ' ').replace('|', '/').trim();
    }

    @Override
    public String toString() {
        return toLogLine();
    }
}
