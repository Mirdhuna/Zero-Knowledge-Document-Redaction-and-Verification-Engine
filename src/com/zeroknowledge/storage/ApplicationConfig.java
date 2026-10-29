package com.zeroknowledge.storage;

import com.zeroknowledge.crypto.KeyManager;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Configuration settings for the Zero-Knowledge Document Redaction and Verification Engine,
 * including local Tesseract OCR settings, rendering DPI, and confidence thresholds.
 */
public final class ApplicationConfig {

    public static final long DEFAULT_MAX_DOCUMENT_BYTES = 50L * 1024L * 1024L; // 50 MB
    public static final String DEFAULT_REDACTED_SUFFIX = ".redacted";
    public static final String DEFAULT_SIGNATURE_EXTENSION = ".zksig";
    public static final String DEFAULT_OCR_LANGUAGE = "eng";
    public static final int DEFAULT_OCR_RENDER_DPI = 300;
    public static final double DEFAULT_MIN_OCR_CONFIDENCE = 0.65;

    private final Path workingDirectory;
    private final Path auditLogPath;
    private final Path keyStoreDirectory;
    private final int defaultRsaKeySizeBits;
    private final long maxDocumentSizeBytes;
    private final boolean persistAuditLogToDisk;

    // Configurable OCR parameters
    private final String tesseractExecutablePath;
    private final String tessdataDirectory;
    private final String ocrLanguage;
    private final int ocrRenderDpi;
    private final double minOcrConfidence;

    public ApplicationConfig(
            Path workingDirectory,
            Path auditLogPath,
            Path keyStoreDirectory,
            int defaultRsaKeySizeBits,
            long maxDocumentSizeBytes,
            boolean persistAuditLogToDisk,
            String tesseractExecutablePath,
            String tessdataDirectory,
            String ocrLanguage,
            int ocrRenderDpi,
            double minOcrConfidence) {
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
        this.tesseractExecutablePath = tesseractExecutablePath == null ? "" : tesseractExecutablePath.trim();
        this.tessdataDirectory = tessdataDirectory == null ? "" : tessdataDirectory.trim();
        this.ocrLanguage = (ocrLanguage == null || ocrLanguage.isBlank()) ? DEFAULT_OCR_LANGUAGE : ocrLanguage.trim();
        this.ocrRenderDpi = ocrRenderDpi >= 72 ? ocrRenderDpi : DEFAULT_OCR_RENDER_DPI;
        this.minOcrConfidence = (minOcrConfidence >= 0.0 && minOcrConfidence <= 1.0)
                ? minOcrConfidence : DEFAULT_MIN_OCR_CONFIDENCE;
    }

    public ApplicationConfig(
            Path workingDirectory,
            Path auditLogPath,
            Path keyStoreDirectory,
            int defaultRsaKeySizeBits,
            long maxDocumentSizeBytes,
            boolean persistAuditLogToDisk) {
        this(
                workingDirectory,
                auditLogPath,
                keyStoreDirectory,
                defaultRsaKeySizeBits,
                maxDocumentSizeBytes,
                persistAuditLogToDisk,
                resolveDefaultTesseractPath(),
                resolveDefaultTessdataDir(),
                resolveDefaultOcrLang(),
                DEFAULT_OCR_RENDER_DPI,
                DEFAULT_MIN_OCR_CONFIDENCE);
    }

    private static String resolveDefaultTesseractPath() {
        String sysProp = System.getProperty("zk.ocr.tesseractPath");
        if (sysProp != null && !sysProp.isBlank()) {
            return sysProp.trim();
        }
        String env = System.getenv("TESSERACT_PATH");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return "";
    }

    private static String resolveDefaultTessdataDir() {
        String sysProp = System.getProperty("zk.ocr.tessdataDir");
        if (sysProp != null && !sysProp.isBlank()) {
            return sysProp.trim();
        }
        String env = System.getenv("TESSDATA_PREFIX");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return "";
    }

    private static String resolveDefaultOcrLang() {
        String sysProp = System.getProperty("zk.ocr.language");
        if (sysProp != null && !sysProp.isBlank()) {
            return sysProp.trim();
        }
        String env = System.getenv("ZK_OCR_LANG");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return DEFAULT_OCR_LANGUAGE;
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

    /**
     * Returns a copy of this configuration with customized OCR parameters.
     */
    public ApplicationConfig withOcrSettings(
            String newTesseractExecutablePath,
            String newTessdataDir,
            String newOcrLanguage,
            int newRenderDpi,
            double newMinConfidence) {
        return new ApplicationConfig(
                workingDirectory,
                auditLogPath,
                keyStoreDirectory,
                defaultRsaKeySizeBits,
                maxDocumentSizeBytes,
                persistAuditLogToDisk,
                newTesseractExecutablePath,
                newTessdataDir,
                newOcrLanguage,
                newRenderDpi,
                newMinConfidence);
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

    public String getTesseractExecutablePath() {
        return tesseractExecutablePath;
    }

    public String getTessdataDirectory() {
        return tessdataDirectory;
    }

    public String getOcrLanguage() {
        return ocrLanguage;
    }

    public int getOcrRenderDpi() {
        return ocrRenderDpi;
    }

    public double getMinOcrConfidence() {
        return minOcrConfidence;
    }
}
