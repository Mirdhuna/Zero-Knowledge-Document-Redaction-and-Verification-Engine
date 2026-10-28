package com.zeroknowledge.storage;

import com.zeroknowledge.crypto.KeyManager;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Configuration settings for the Zero-Knowledge Document Redaction and Verification Engine.
 */
public final class ApplicationConfig {

    public static final long DEFAULT_MAX_DOCUMENT_BYTES = 50L * 1024L * 1024L; // 50 MB for text/CSV processing
    public static final String DEFAULT_REDACTED_SUFFIX = ".redacted";
    public static final String DEFAULT_SIGNATURE_EXTENSION = ".zksig";

    private final Path workingDirectory;
    private final Path auditLogPath;
    private final Path keyStoreDirectory;
    private final int defaultRsaKeySizeBits;
    private final long maxDocumentSizeBytes;
    private final boolean persistAuditLogToDisk;

    public ApplicationConfig(
            Path workingDirectory,
            Path auditLogPath,
            Path keyStoreDirectory,
            int defaultRsaKeySizeBits,
            long maxDocumentSizeBytes,
            boolean persistAuditLogToDisk) {
        this.workingDirectory = Objects.requireNonNull(workingDirectory, "workingDirectory must not be null")
                .toAbsolutePath().normalize();
        this.auditLogPath = Objects.requireNonNull(auditLogPath, "auditLogPath must not be null")
                .toAbsolutePath().normalize();
        this.keyStoreDirectory = Objects.requireNonNull(keyStoreDirectory, "keyStoreDirectory must not be null")
                .toAbsolutePath().normalize();
        if (defaultRsaKeySizeBits < KeyManager.MIN_KEY_SIZE || defaultRsaKeySizeBits > KeyManager.MAX_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid default RSA key size: " + defaultRsaKeySizeBits);
        }
        if (maxDocumentSizeBytes <= 0) {
            throw new IllegalArgumentException("maxDocumentSizeBytes must be positive");
        }
        this.defaultRsaKeySizeBits = defaultRsaKeySizeBits;
        this.maxDocumentSizeBytes = maxDocumentSizeBytes;
        this.persistAuditLogToDisk = persistAuditLogToDisk;
    }

    /**
     * Creates a default configuration anchored in the specified base directory.
     */
    public static ApplicationConfig withBaseDirectory(Path baseDir) {
        Objects.requireNonNull(baseDir, "baseDir must not be null");
        Path normalized = baseDir.toAbsolutePath().normalize();
        return new ApplicationConfig(
                normalized,
                normalized.resolve("logs").resolve("zk_audit.log"),
                normalized.resolve("keys"),
                KeyManager.DEFAULT_KEY_SIZE,
                DEFAULT_MAX_DOCUMENT_BYTES,
                true);
    }

    /**
     * Creates a default configuration in the current working directory.
     */
    public static ApplicationConfig createDefault() {
        return withBaseDirectory(Path.of("."));
    }

    public Path getWorkingDirectory() {
        return workingDirectory;
    }

    public Path getAuditLogPath() {
        return auditLogPath;
    }

    public Path getKeyStoreDirectory() {
        return keyStoreDirectory;
    }

    public int getDefaultRsaKeySizeBits() {
        return defaultRsaKeySizeBits;
    }

    public long getMaxDocumentSizeBytes() {
        return maxDocumentSizeBytes;
    }

    public boolean isPersistAuditLogToDisk() {
        return persistAuditLogToDisk;
    }
}
