package com.zeroknowledge.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Audit log entry for locally performed operations.
 */
public class OperationRecord {
    public enum OperationType {
        SCAN,
        REDACT,
        SIGN,
        VERIFY,
        KEY_GENERATION,
        KEY_EXPORT,
        KEY_IMPORT
    }

    public enum Status {
        SUCCESS,
        FAILED,
        CANCELLED,
        WARNING
    }

    private final String id;
    private final long timestamp;
    private final OperationType operationType;
    private final String documentIdentifier;
    private final Status status;
    private final String details;

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public OperationRecord(String id, long timestamp, OperationType operationType,
                           String documentIdentifier, Status status, String details) {
        this.id = id;
        this.timestamp = timestamp;
        this.operationType = operationType;
        this.documentIdentifier = documentIdentifier != null ? documentIdentifier : "-";
        this.status = status;
        this.details = details != null ? details : "";
    }

    public static OperationRecord create(OperationType type, String documentIdentifier,
                                         Status status, String details) {
        String id = "OP-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
        return new OperationRecord(id, System.currentTimeMillis(), type, documentIdentifier, status, details);
    }

    public String getId() {
        return id;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getFormattedTimestamp() {
        return FORMATTER.format(Instant.ofEpochMilli(timestamp));
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public String getDocumentIdentifier() {
        return documentIdentifier;
    }

    public Status getStatus() {
        return status;
    }

    public String getDetails() {
        return details;
    }
}
