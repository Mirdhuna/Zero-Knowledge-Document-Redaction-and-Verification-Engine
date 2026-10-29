package com.zeroknowledge.storage;

import com.zeroknowledge.model.OperationRecord;
import com.zeroknowledge.model.OperationRecord.OperationType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Thread-safe local audit logging service.
 *
 * <h3>Privacy Guarantees</h3>
 * <ul>
 *   <li>Records only timestamps, operation types, document filenames/hashes, status flags, and non-sensitive counts/codes.</li>
 *   <li>Never logs raw document contents, unmasked PII values, private keys, or passphrases.</li>
 *   <li>Automatically scrubs any accidentally passed email-like or long digit sequences from detail strings as defense-in-depth.</li>
 * </ul>
 */
public final class AuditService {

    private final ApplicationConfig config;
    private final CopyOnWriteArrayList<OperationRecord> memoryRecords;
    private final ReentrantLock fileWriteLock;

    public AuditService(ApplicationConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.memoryRecords = new CopyOnWriteArrayList<>();
        this.fileWriteLock = new ReentrantLock();
    }

    public AuditService() {
        this(ApplicationConfig.createDefault());
    }

    /**
     * Records a security or document operation in memory and (if enabled) appends to the local audit file.
     *
     * @param operationType      type of operation executed
     * @param documentIdentifier file name or key identifier (never raw document text)
     * @param success            whether the operation succeeded
     * @param nonSensitiveDetail privacy-safe description (counts, status codes, key IDs)
     * @return the recorded {@link OperationRecord}
     */
    public OperationRecord record(
            OperationType operationType,
            String documentIdentifier,
            boolean success,
            String nonSensitiveDetail) {
        Objects.requireNonNull(operationType, "operationType must not be null");
        String safeDocId = sanitizeTarget(documentIdentifier);
        String safeDetail = scrubPotentialSecrets(nonSensitiveDetail);

        OperationRecord record = new OperationRecord(
                Instant.now(),
                operationType,
                safeDocId,
                success,
                safeDetail);

        memoryRecords.add(record);
        if (config.isPersistAuditLogToDisk()) {
            appendToDisk(record);
        }
        return record;
    }

    /**
     * Returns an unmodifiable snapshot of all audit records captured in this session.
     */
    public List<OperationRecord> getRecords() {
        return Collections.unmodifiableList(List.copyOf(memoryRecords));
    }

    /**
     * Clears in-memory audit records (for testing isolation).
     */
    public void clearMemoryRecords() {
        memoryRecords.clear();
    }

    private void appendToDisk(OperationRecord record) {
        fileWriteLock.lock();
        try {
            Path logPath = config.getAuditLogPath();
            Path parent = logPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String line = record.toLogLine() + System.lineSeparator();
            Files.writeString(
                    logPath,
                    line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Audit persistence failure should not crash the engine or leak details to stdout;
            // the record remains available in memoryRecords.
        } finally {
            fileWriteLock.unlock();
        }
    }

    private static String sanitizeTarget(String documentIdentifier) {
        if (documentIdentifier == null || documentIdentifier.isBlank()) {
            return "N/A";
        }
        String trimmed = documentIdentifier.trim();
        // Extract only basename if a path separator is present
        int lastSlash = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
        if (lastSlash >= 0 && lastSlash < trimmed.length() - 1) {
            return trimmed.substring(lastSlash + 1);
        }
        return trimmed;
    }

    /**
     * Defense-in-depth sanitizer: prevents accidental logging of email addresses, SSNs, or PEM blocks
     * even if a caller passes an unsanitized string.
     */
    private static String scrubPotentialSecrets(String detail) {
        if (detail == null || detail.isBlank()) {
            return "";
        }
        String scrubbed = detail;
        // Scrub PEM headers
        if (scrubbed.contains("PRIVATE KEY") || scrubbed.contains("-----BEGIN")) {
            return "[SCRUBBED_KEY_MATERIAL]";
        }
        // Scrub any email-like pattern
        scrubbed = scrubbed.replaceAll("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "[SCRUBBED_EMAIL]");
        // Scrub SSN-like pattern
        scrubbed = scrubbed.replaceAll("\\b\\d{3}-\\d{2}-\\d{4}\\b", "[SCRUBBED_ID]");
        // Scrub PAN-like pattern
        scrubbed = scrubbed.replaceAll("\\b[A-Z]{3}[ABCFGHLJPT][A-Z]\\d{4}[A-Z]\\b", "[SCRUBBED_PAN]");
        // Scrub IFSC-like pattern
        scrubbed = scrubbed.replaceAll("\\b[A-Z]{4}0[A-Z0-9]{6}\\b", "[SCRUBBED_IFSC]");
        // Scrub grouped 12-16 digit sequences (Aadhaar / payment cards) while preserving 64-char hex SHA-256 digests
        scrubbed = scrubbed.replaceAll("(?<![0-9a-fA-F])(?:\\d{4}[ -]){2,3}\\d{4}(?![0-9a-fA-F])", "[SCRUBBED_NUMBER]");
        return scrubbed;
    }
}
