package com.zeroknowledge.model;

import com.zeroknowledge.document.DocumentFormat;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;

/**
 * Immutable metadata describing a document on disk.
 */
public final class DocumentMetadata {

    private final Path filePath;
    private final String fileName;
    private final DocumentFormat format;
    private final long sizeBytes;
    private final String sha256Digest;
    private final Instant lastModifiedTime;
    private final boolean readable;

    public DocumentMetadata(
            Path filePath,
            String fileName,
            DocumentFormat format,
            long sizeBytes,
            String sha256Digest,
            Instant lastModifiedTime,
            boolean readable) {
        this.filePath = Objects.requireNonNull(filePath, "filePath must not be null");
        this.fileName = Objects.requireNonNull(fileName, "fileName must not be null");
        this.format = Objects.requireNonNull(format, "format must not be null");
        this.sizeBytes = sizeBytes;
        this.sha256Digest = Objects.requireNonNull(sha256Digest, "sha256Digest must not be null");
        this.lastModifiedTime = Objects.requireNonNull(lastModifiedTime, "lastModifiedTime must not be null");
        this.readable = readable;
    }

    public Path getFilePath() {
        return filePath;
    }

    public String getFileName() {
        return fileName;
    }

    public DocumentFormat getFormat() {
        return format;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getSha256Digest() {
        return sha256Digest;
    }

    public Instant getLastModifiedTime() {
        return lastModifiedTime;
    }

    public boolean isReadable() {
        return readable;
    }

    @Override
    public String toString() {
        return "DocumentMetadata{"
                + "fileName='" + fileName + '\''
                + ", format=" + format
                + ", sizeBytes=" + sizeBytes
                + ", sha256='" + sha256Digest + '\''
                + ", lastModified=" + lastModifiedTime
                + ", readable=" + readable
                + '}';
    }
}
