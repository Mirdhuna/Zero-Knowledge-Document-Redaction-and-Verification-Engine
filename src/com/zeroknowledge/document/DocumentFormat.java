package com.zeroknowledge.document;

import java.nio.file.Path;
import java.util.Locale;

/**
 * Supported document formats and their explicit capability boundaries.
 */
public enum DocumentFormat {
    TXT(
            "Plain Text Document",
            ".txt",
            true,
            true,
            true,
            true,
            "Full UTF-8 text scanning, user-approved redaction, SHA-256 hashing, and RSA digital signatures."
    ),
    CSV(
            "Comma-Separated Values",
            ".csv",
            true,
            true,
            true,
            true,
            "RFC-4180 compliant cell-level scanning and redaction preserving quotes, embedded commas, and multiline cells."
    ),
    PDF(
            "Portable Document Format",
            ".pdf",
            true,
            true,
            true,
            true,
            "Pure-JDK content-stream decompression, sensitive entity detection, stream redaction, SHA-256 hashing, and RSA digital signatures."
    ),
    UNSUPPORTED(
            "Unsupported Format",
            "",
            false,
            false,
            false,
            false,
            "Unsupported file extension."
    );

    private final String displayName;
    private final String extension;
    private final boolean textExtractionSupported;
    private final boolean redactionSupported;
    private final boolean hashingSupported;
    private final boolean signingAndVerificationSupported;
    private final String capabilityDescription;

    DocumentFormat(
            String displayName,
            String extension,
            boolean textExtractionSupported,
            boolean redactionSupported,
            boolean hashingSupported,
            boolean signingAndVerificationSupported,
            String capabilityDescription) {
        this.displayName = displayName;
        this.extension = extension;
        this.textExtractionSupported = textExtractionSupported;
        this.redactionSupported = redactionSupported;
        this.hashingSupported = hashingSupported;
        this.signingAndVerificationSupported = signingAndVerificationSupported;
        this.capabilityDescription = capabilityDescription;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getExtension() {
        return extension;
    }

    public boolean isTextExtractionSupported() {
        return textExtractionSupported;
    }

    public boolean isRedactionSupported() {
        return redactionSupported;
    }

    public boolean isHashingSupported() {
        return hashingSupported;
    }

    public boolean isSigningAndVerificationSupported() {
        return signingAndVerificationSupported;
    }

    public String getCapabilityDescription() {
        return capabilityDescription;
    }

    /**
     * Resolves a {@link DocumentFormat} from a file path based on its extension.
     */
    public static DocumentFormat fromPath(Path path) {
        if (path == null || path.getFileName() == null) {
            return UNSUPPORTED;
        }
        return fromFileName(path.getFileName().toString());
    }

    /**
     * Resolves a {@link DocumentFormat} from a file name string.
     */
    public static DocumentFormat fromFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return UNSUPPORTED;
        }
        String lower = fileName.trim().toLowerCase(Locale.ROOT);
        if (lower.endsWith(".txt")) {
            return TXT;
        }
        if (lower.endsWith(".csv")) {
            return CSV;
        }
        if (lower.endsWith(".pdf")) {
            return PDF;
        }
        return UNSUPPORTED;
    }
}
