package com.zeroknowledge.crypto;

import com.zeroknowledge.exception.DocumentProcessingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Cryptographic SHA-256 hashing service using standard JCA {@link MessageDigest}.
 * Supports streaming large files without loading the entire file into memory.
 *
 * <p>Thread-safe: stateless service creating a fresh {@link MessageDigest} per operation.
 */
public final class HashService {

    public static final String ALGORITHM = "SHA-256";
    private static final int STREAM_BUFFER_SIZE = 64 * 1024; // 64 KB chunks
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    public HashService() {
        // Verify SHA-256 availability on construction
        createDigest();
    }

    /**
     * Calculates the lowercase hexadecimal SHA-256 digest of a file's exact bytes using streaming I/O.
     *
     * @param filePath path to an existing regular file
     * @return 64-character lowercase hexadecimal SHA-256 digest
     * @throws DocumentProcessingException if the file does not exist, is a directory, or an I/O failure occurs
     */
    public String calculateSha256(Path filePath) throws DocumentProcessingException {
        Objects.requireNonNull(filePath, "filePath must not be null");
        Path normalized = filePath.toAbsolutePath().normalize();
        if (!Files.exists(normalized)) {
            throw new DocumentProcessingException("File does not exist for hashing: " + normalized.getFileName());
        }
        if (!Files.isRegularFile(normalized)) {
            throw new DocumentProcessingException("Path is not a regular file: " + normalized.getFileName());
        }
        if (!Files.isReadable(normalized)) {
            throw new DocumentProcessingException("File is not readable: " + normalized.getFileName());
        }

        MessageDigest digest = createDigest();
        byte[] buffer = new byte[STREAM_BUFFER_SIZE];
        try (InputStream in = Files.newInputStream(normalized)) {
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new DocumentProcessingException(
                    "I/O failure while reading file for SHA-256 digest: " + normalized.getFileName(), e);
        }

        byte[] hashBytes = digest.digest();
        return HEX_FORMAT.formatHex(hashBytes);
    }

    /**
     * Calculates the lowercase hexadecimal SHA-256 digest of an in-memory byte array.
     *
     * @param data byte array to hash
     * @return 64-character lowercase hexadecimal SHA-256 digest
     */
    public String calculateSha256(byte[] data) {
        Objects.requireNonNull(data, "data must not be null");
        MessageDigest digest = createDigest();
        return HEX_FORMAT.formatHex(digest.digest(data));
    }

    /**
     * Calculates the lowercase hexadecimal SHA-256 digest of a UTF-8 string.
     *
     * @param text string to hash
     * @return 64-character lowercase hexadecimal SHA-256 digest
     */
    public String calculateSha256ForText(String text) {
        Objects.requireNonNull(text, "text must not be null");
        return calculateSha256(text.getBytes(StandardCharsets.UTF_8));
    }

    private static MessageDigest createDigest() {
        try {
            return MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Standard JCA algorithm " + ALGORITHM + " is unavailable", e);
        }
    }
}
