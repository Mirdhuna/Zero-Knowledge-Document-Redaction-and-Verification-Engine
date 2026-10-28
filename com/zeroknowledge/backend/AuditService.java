package com.zeroknowledge.backend;

import com.zeroknowledge.model.OperationRecord;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Backend service for tracking and recording security-critical operations locally.
 * Preserves an audit trail without storing sensitive document contents or private keys.
 */
public class AuditService {

    private final List<OperationRecord> records = new CopyOnWriteArrayList<>();
    private final File auditLogFile;

    public AuditService() {
        File home = new File(System.getProperty("user.home"));
        File baseDir = (home.exists() && home.canWrite()) ? home : new File(System.getProperty("user.dir"));
        this.auditLogFile = new File(baseDir, ".zk_redaction_audit.log");
        loadRecordsFromDisk();
    }

    public AuditService(File customLogFile) {
        this.auditLogFile = customLogFile;
        loadRecordsFromDisk();
    }

    public synchronized void logOperation(OperationRecord.OperationType type,
                                          String documentIdentifier,
                                          OperationRecord.Status status,
                                          String nonSensitiveDetails) {
        OperationRecord record = OperationRecord.create(type, documentIdentifier, status, nonSensitiveDetails);
        records.add(0, record); // Most recent first
        appendRecordToDisk(record);
    }

    public List<OperationRecord> getRecords() {
        return Collections.unmodifiableList(records);
    }

    public List<OperationRecord> filterRecords(OperationRecord.OperationType typeFilter,
                                               OperationRecord.Status statusFilter) {
        List<OperationRecord> filtered = new ArrayList<>();
        for (OperationRecord r : records) {
            boolean matchType = (typeFilter == null || r.getOperationType() == typeFilter);
            boolean matchStatus = (statusFilter == null || r.getStatus() == statusFilter);
            if (matchType && matchStatus) {
                filtered.add(r);
            }
        }
        return filtered;
    }

    public synchronized void clearHistory() {
        records.clear();
        if (auditLogFile.exists()) {
            try {
                Files.writeString(auditLogFile.toPath(), "", StandardCharsets.UTF_8);
            } catch (IOException e) {
                System.err.println("Warning: could not clear audit log on disk: " + e.getMessage());
            }
        }
    }

    public int getScannedCount() {
        int count = 0;
        for (OperationRecord r : records) {
            if (r.getOperationType() == OperationRecord.OperationType.SCAN &&
                    r.getStatus() == OperationRecord.Status.SUCCESS) {
                count++;
            }
        }
        return count;
    }

    public int getRedactedCount() {
        int count = 0;
        for (OperationRecord r : records) {
            if (r.getOperationType() == OperationRecord.OperationType.REDACT &&
                    r.getStatus() == OperationRecord.Status.SUCCESS) {
                count++;
            }
        }
        return count;
    }

    public int getVerifiedCount() {
        int count = 0;
        for (OperationRecord r : records) {
            if (r.getOperationType() == OperationRecord.OperationType.VERIFY &&
                    r.getStatus() == OperationRecord.Status.SUCCESS) {
                count++;
            }
        }
        return count;
    }

    public int getTotalOperationsCount() {
        return records.size();
    }

    private void appendRecordToDisk(OperationRecord record) {
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(auditLogFile, true), StandardCharsets.UTF_8))) {
            // TSV format: id \t timestamp \t type \t docId \t status \t details
            String safeDoc = record.getDocumentIdentifier().replace("\t", " ").replace("\n", " ");
            String safeDetails = record.getDetails().replace("\t", " ").replace("\n", " ");
            out.println(record.getId() + "\t" + record.getTimestamp() + "\t" +
                    record.getOperationType().name() + "\t" + safeDoc + "\t" +
                    record.getStatus().name() + "\t" + safeDetails);
        } catch (IOException e) {
            System.err.println("Warning: could not write to audit log: " + e.getMessage());
        }
    }

    private void loadRecordsFromDisk() {
        if (!auditLogFile.exists()) return;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(auditLogFile), StandardCharsets.UTF_8))) {
            String line;
            List<OperationRecord> loaded = new ArrayList<>();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\t", 6);
                if (parts.length >= 6) {
                    try {
                        String id = parts[0];
                        long ts = Long.parseLong(parts[1]);
                        OperationRecord.OperationType type = OperationRecord.OperationType.valueOf(parts[2]);
                        String doc = parts[3];
                        OperationRecord.Status status = OperationRecord.Status.valueOf(parts[4]);
                        String details = parts[5];
                        loaded.add(new OperationRecord(id, ts, type, doc, status, details));
                    } catch (Exception ignored) {
                    }
                }
            }
            // Reverse so newest are first
            Collections.reverse(loaded);
            records.addAll(loaded);
        } catch (IOException e) {
            System.err.println("Warning: could not read audit log: " + e.getMessage());
        }
    }
}
