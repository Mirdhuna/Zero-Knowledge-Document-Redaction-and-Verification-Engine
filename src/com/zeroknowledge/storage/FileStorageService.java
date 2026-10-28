package com.zeroknowledge.storage;

import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.DocumentMetadata;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Objects;

/**
 * Provides safe file validation, strict UTF-8 reading, non-overwriting output path resolution,
 * and atomic temporary-file writes.
 */
public final class FileStorageService {

    private final ApplicationConfig config;
    private final HashService hashService;

    public FileStorageService(ApplicationConfig config, HashService hashService) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
    }

    public FileStorageService() {
        this(ApplicationConfig.createDefault(), new HashService());
    }

    /**
     * Validates that a source path exists, is a regular readable file, and does not exceed size limits.
     */
    public Path validateReadableSourceFile(Path sourcePath) throws DocumentProcessingException {
        if (sourcePath == null) {
            throw new DocumentProcessingException("Source file path must not be null");
        }
        String rawPathStr = sourcePath.toString();
        if (rawPathStr.isBlank() || rawPathStr.indexOf('\0') >= 0) {
            throw new DocumentProcessingException("Source file path is empty or contains invalid characters");
        }

        Path normalized = sourcePath.toAbsolutePath().normalize();
        if (!Files.exists(normalized)) {
            throw new DocumentProcessingException("Source file does not exist: " + normalized.getFileName());
        }
        if (Files.isDirectory(normalized) || !Files.isRegularFile(normalized)) {
            throw new DocumentProcessingException("Source path is not a regular file: " + normalized.getFileName());
        }
        if (!Files.isReadable(normalized)) {
            throw new DocumentProcessingException("Source file is not readable: " + normalized.getFileName());
        }
        try {
            long size = Files.size(normalized);
            if (size > config.getMaxDocumentSizeBytes()) {
                throw new DocumentProcessingException(
                        "File size (" + size + " bytes) exceeds maximum allowed limit ("
                                + config.getMaxDocumentSizeBytes() + " bytes)");
            }
        } catch (IOException e) {
            throw new DocumentProcessingException("Failed to inspect size of file: " + normalized.getFileName(), e);
        }
        return normalized;
    }

    /**
     * Inspects a file and constructs its {@link DocumentMetadata} including SHA-256 digest.
     */
    public DocumentMetadata inspectDocument(Path filePath) throws DocumentProcessingException {
        Path normalized = validateReadableSourceFile(filePath);
        try {
            long size = Files.size(normalized);
            Instant lastModified = Files.getLastModifiedTime(normalized).toInstant();
            DocumentFormat format = DocumentFormat.fromPath(normalized);
            String sha256 = hashService.calculateSha256(normalized);
            return new DocumentMetadata(
                    normalized,
                    normalized.getFileName().toString(),
                    format,
                    size,
                    sha256,
                    lastModified,
                    Files.isReadable(normalized));
        } catch (IOException e) {
            throw new DocumentProcessingException("Failed to read metadata for file: " + normalized.getFileName(), e);
        }
    }

    /**
     * Strictly reads a file as UTF-8 text, rejecting malformed byte sequences or unexpected binary data.
     * Strips an optional leading UTF-8 BOM (U+FEFF) if present at index 0.
     */
    public String readUtf8Text(Path sourcePath) throws DocumentProcessingException {
        Path normalized = validateReadableSourceFile(sourcePath);
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(normalized);
        } catch (IOException e) {
            throw new DocumentProcessingException("I/O error reading file: " + normalized.getFileName(), e);
        }
        if (bytes.length == 0) {
            return "";
        }

        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer charBuffer = decoder.decode(ByteBuffer.wrap(bytes));
            String content = charBuffer.toString();
            if (!content.isEmpty() && content.charAt(0) == '\uFEFF') {
                return content.substring(1);
            }
            return content;
        } catch (CharacterCodingException e) {
            throw new DocumentProcessingException(
                    "File is not valid UTF-8 text: " + normalized.getFileName(), e);
        }
    }

    /**
     * Resolves a safe default output path for a redacted document without overwriting the source file.
     * Example: {@code report.txt} -> {@code report.redacted.txt}
     */
    public Path resolveDefaultRedactedOutputPath(Path sourcePath) throws RedactionException {
        if (sourcePath == null || sourcePath.getFileName() == null) {
            throw new RedactionException("Cannot derive output path from null source path");
        }
        Path normalizedSource = sourcePath.toAbsolutePath().normalize();
        String fileName = normalizedSource.getFileName().toString();
        int dotIndex = fileName.lastIndexOf('.');
        String baseName = (dotIndex > 0) ? fileName.substring(0, dotIndex) : fileName;
        String extension = (dotIndex > 0) ? fileName.substring(dotIndex) : "";

        Path parent = normalizedSource.getParent();
        Path candidate = (parent != null)
                ? parent.resolve(baseName + ApplicationConfig.DEFAULT_REDACTED_SUFFIX + extension)
                : Path.of(baseName + ApplicationConfig.DEFAULT_REDACTED_SUFFIX + extension).toAbsolutePath().normalize();

        if (candidate.equals(normalizedSource)) {
            throw new RedactionException("Resolved output path collides with source path");
        }
        return candidate;
    }

    /**
     * Resolves a default detached signature file path for a given document.
     * Example: {@code report.redacted.txt} -> {@code report.redacted.txt.zksig}
     */
    public Path resolveDefaultSignaturePath(Path documentPath) {
        Objects.requireNonNull(documentPath, "documentPath must not be null");
        Path normalized = documentPath.toAbsolutePath().normalize();
        String sigFileName = normalized.getFileName().toString() + ApplicationConfig.DEFAULT_SIGNATURE_EXTENSION;
        Path parent = normalized.getParent();
        return (parent != null) ? parent.resolve(sigFileName) : Path.of(sigFileName).toAbsolutePath().normalize();
    }

    /**
     * Validates that {@code destinationPath} is distinct from {@code sourcePath}, is not a directory,
     * and can be safely written via a temporary file and atomic replacement.
     */
    public Path validateSafeOutputDestination(Path sourcePath, Path destinationPath, boolean allowOverwriteTarget)
            throws RedactionException {
        if (sourcePath == null || destinationPath == null) {
            throw new RedactionException("Source and destination paths must not be null");
        }
        Path normSource = sourcePath.toAbsolutePath().normalize();
        Path normDest = destinationPath.toAbsolutePath().normalize();

        if (normSource.equals(normDest)) {
            throw new RedactionException(
                    "Refusing to overwrite original source document: " + normSource.getFileName());
        }
        try {
            if (Files.exists(normDest) && Files.exists(normSource) && Files.isSameFile(normSource, normDest)) {
                throw new RedactionException(
                        "Destination path points to the same underlying file as the source document");
            }
        } catch (IOException e) {
            throw new RedactionException("Unable to verify path equivalence for output file", e);
        }

        if (Files.exists(normDest)) {
            if (Files.isDirectory(normDest)) {
                throw new RedactionException("Destination path is an existing directory: " + normDest.getFileName());
            }
            if (!allowOverwriteTarget) {
                throw new RedactionException(
                        "Destination file already exists and overwrite is disabled: " + normDest.getFileName());
            }
            if (!Files.isWritable(normDest)) {
                throw new RedactionException("Existing destination file is not writable: " + normDest.getFileName());
            }
        }
        return normDest;
    }

    /**
     * Writes UTF-8 content to a temporary file in the target directory, verifies its readability,
     * and moves it into place at {@code destinationPath}, preventing partial writes and source overwrites.
     */
    public Path writeRedactedUtf8Safely(
            Path sourcePath,
            Path destinationPath,
            String redactedContent,
            boolean allowOverwriteDestination) throws RedactionException {
        Objects.requireNonNull(redactedContent, "redactedContent must not be null");
        Path validatedDest = validateSafeOutputDestination(sourcePath, destinationPath, allowOverwriteDestination);
        Path parent = validatedDest.getParent();

        Path tempFile = null;
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tempDir = (parent != null) ? parent : Path.of(".").toAbsolutePath().normalize();
            tempFile = Files.createTempFile(tempDir, "zk_redact_", ".tmp");
            Files.writeString(tempFile, redactedContent, StandardCharsets.UTF_8);

            // Validate saved temp file before moving into final destination
            if (!Files.exists(tempFile) || !Files.isReadable(tempFile)) {
                throw new RedactionException("Temporary redacted output failed readability validation");
            }
            byte[] expectedBytes = redactedContent.getBytes(StandardCharsets.UTF_8);
            long writtenSize = Files.size(tempFile);
            if (writtenSize != expectedBytes.length) {
                throw new RedactionException("Written byte count mismatch during output validation");
            }

            try {
                if (allowOverwriteDestination) {
                    Files.move(tempFile, validatedDest, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(tempFile, validatedDest, StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException moveEx) {
                if (allowOverwriteDestination) {
                    Files.move(tempFile, validatedDest, StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(tempFile, validatedDest);
                }
            }
            return validatedDest;
        } catch (IOException e) {
            throw new RedactionException(
                    "Failed to write redacted output to destination: " + validatedDest.getFileName(), e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {
                    // Best-effort cleanup
                }
            }
        }
    }
}
