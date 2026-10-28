package com.zeroknowledge.crypto;

import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.exception.SignatureVerificationException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Versioned detached signature metadata and signature container.
 *
 * <h3>Signed-Byte Representation Specification</h3>
 * <p>The cryptographic signature ({@code SHA256withRSA}) is computed directly and exclusively
 * over the exact raw bytes of the target document file on disk (from byte 0 to EOF).
 * Metadata fields stored in this sidecar file are informational/organizational and are
 * <strong>never</strong> trusted as a substitute for verifying the cryptographic signature
 * against the actual document bytes and an explicitly trusted {@link java.security.PublicKey}.
 */
public final class SignatureMetadata {

    public static final String CURRENT_FORMAT_VERSION = "ZK-SIG-1.0";
    public static final String REQUIRED_ALGORITHM = "SHA256withRSA";
    private static final Pattern SHA256_HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]{64}$");

    private final String formatVersion;
    private final String signatureAlgorithm;
    private final DocumentFormat documentFormat;
    private final String documentDigest;
    private final String publicKeyId;
    private final String signatureReference;
    private final Instant createdAt;
    private final String signatureBase64;

    public SignatureMetadata(
            String formatVersion,
            String signatureAlgorithm,
            DocumentFormat documentFormat,
            String documentDigest,
            String publicKeyId,
            String signatureReference,
            Instant createdAt,
            String signatureBase64) throws SignatureVerificationException {
        this.formatVersion = requireNonBlank(formatVersion, "formatVersion");
        this.signatureAlgorithm = requireNonBlank(signatureAlgorithm, "signatureAlgorithm");
        this.documentFormat = Objects.requireNonNull(documentFormat, "documentFormat must not be null");
        this.documentDigest = requireNonBlank(documentDigest, "documentDigest").toLowerCase();
        this.publicKeyId = requireNonBlank(publicKeyId, "publicKeyId");
        this.signatureReference = requireNonBlank(signatureReference, "signatureReference");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.signatureBase64 = requireNonBlank(signatureBase64, "signatureBase64");

        validateFields();
    }

    private void validateFields() throws SignatureVerificationException {
        if (!CURRENT_FORMAT_VERSION.equals(formatVersion)) {
            throw new SignatureVerificationException("Unsupported signature format version: " + formatVersion);
        }
        if (!REQUIRED_ALGORITHM.equals(signatureAlgorithm)) {
            throw new SignatureVerificationException("Unsupported signature algorithm: " + signatureAlgorithm);
        }
        if (documentFormat == DocumentFormat.UNSUPPORTED) {
            throw new SignatureVerificationException("Signature metadata references an unsupported document format");
        }
        if (!SHA256_HEX_PATTERN.matcher(documentDigest).matches()) {
            throw new SignatureVerificationException("Invalid SHA-256 hex digest in signature metadata");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(signatureBase64);
            if (decoded.length < 64) {
                throw new SignatureVerificationException("Decoded signature bytes are shorter than minimum RSA length");
            }
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Invalid Base64 signature encoding in metadata", e);
        }
    }

    private static String requireNonBlank(String value, String fieldName) throws SignatureVerificationException {
        if (value == null || value.isBlank()) {
            throw new SignatureVerificationException("Missing required signature metadata field: " + fieldName);
        }
        return value.trim();
    }

    public String getFormatVersion() {
        return formatVersion;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public DocumentFormat getDocumentFormat() {
        return documentFormat;
    }

    public String getDocumentDigest() {
        return documentDigest;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }

    public String getSignatureReference() {
        return signatureReference;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getSignatureBase64() {
        return signatureBase64;
    }

    /**
     * Decodes and returns a defensive copy of the raw RSA signature bytes.
     */
    public byte[] getSignatureBytes() throws SignatureVerificationException {
        try {
            return Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Invalid Base64 signature encoding", e);
        }
    }

    /**
     * Serializes this metadata to a deterministic UTF-8 key-value representation.
     */
    public String serialize() {
        Properties props = new Properties();
        props.setProperty("formatVersion", formatVersion);
        props.setProperty("signatureAlgorithm", signatureAlgorithm);
        props.setProperty("documentFormat", documentFormat.name());
        props.setProperty("documentDigest", documentDigest);
        props.setProperty("publicKeyId", publicKeyId);
        props.setProperty("signatureReference", signatureReference);
        props.setProperty("createdAt", createdAt.toString());
        props.setProperty("signatureBase64", signatureBase64);

        try (StringWriter writer = new StringWriter()) {
            props.store(writer, "Zero-Knowledge Detached Signature Bundle (" + CURRENT_FORMAT_VERSION + ")");
            return writer.toString();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected StringWriter IOException", e);
        }
    }

    /**
     * Saves this detached signature metadata atomically to the given path.
     */
    public void saveToFile(Path destinationPath) throws SignatureVerificationException {
        Objects.requireNonNull(destinationPath, "destinationPath must not be null");
        Path normalized = destinationPath.toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tempFile = Files.createTempFile(parent != null ? parent : Path.of("."), "zksig_", ".tmp");
            try {
                Files.writeString(tempFile, serialize(), StandardCharsets.UTF_8);
                Files.move(tempFile, normalized, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException moveEx) {
                // Fallback if ATOMIC_MOVE is unsupported on filesystem
                Files.move(tempFile, normalized, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tempFile);
            }
        } catch (IOException e) {
            throw new SignatureVerificationException(
                    "Failed to save detached signature file: " + normalized.getFileName(), e);
        }
    }

    /**
     * Parses and validates a {@link SignatureMetadata} instance from a serialized string.
     */
    public static SignatureMetadata parse(String content) throws SignatureVerificationException {
        if (content == null || content.isBlank()) {
            throw new SignatureVerificationException("Signature metadata content is empty");
        }
        Properties props = new Properties();
        try (Reader reader = new StringReader(content)) {
            props.load(reader);
        } catch (IOException | IllegalArgumentException e) {
            throw new SignatureVerificationException("Malformed signature metadata structure", e);
        }

        String version = props.getProperty("formatVersion");
        String algorithm = props.getProperty("signatureAlgorithm");
        String formatStr = props.getProperty("documentFormat");
        String digest = props.getProperty("documentDigest");
        String keyId = props.getProperty("publicKeyId");
        String sigRef = props.getProperty("signatureReference");
        String createdAtStr = props.getProperty("createdAt");
        String sigB64 = props.getProperty("signatureBase64");

        if (formatStr == null || createdAtStr == null) {
            throw new SignatureVerificationException("Missing documentFormat or createdAt in signature metadata");
        }

        DocumentFormat docFormat;
        try {
            docFormat = DocumentFormat.valueOf(formatStr.trim());
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Invalid documentFormat in signature metadata: " + formatStr, e);
        }

        Instant createdInstant;
        try {
            createdInstant = Instant.parse(createdAtStr.trim());
        } catch (DateTimeParseException e) {
            throw new SignatureVerificationException("Invalid ISO-8601 timestamp in signature metadata", e);
        }

        return new SignatureMetadata(
                version,
                algorithm,
                docFormat,
                digest,
                keyId,
                sigRef,
                createdInstant,
                sigB64);
    }

    /**
     * Loads and validates a {@link SignatureMetadata} from a detached signature file.
     */
    public static SignatureMetadata loadFromFile(Path signaturePath) throws SignatureVerificationException {
        Objects.requireNonNull(signaturePath, "signaturePath must not be null");
        Path normalized = signaturePath.toAbsolutePath().normalize();
        if (!Files.exists(normalized) || !Files.isRegularFile(normalized)) {
            throw new SignatureVerificationException("Detached signature file does not exist: " + normalized.getFileName());
        }
        try {
            long size = Files.size(normalized);
            if (size == 0) {
                throw new SignatureVerificationException("Detached signature file is empty: " + normalized.getFileName());
            }
            if (size > 1024 * 1024) {
                throw new SignatureVerificationException("Detached signature file exceeds maximum safe size (1 MB)");
            }
            String content = Files.readString(normalized, StandardCharsets.UTF_8);
            return parse(content);
        } catch (IOException e) {
            throw new SignatureVerificationException(
                    "Unable to read detached signature file: " + normalized.getFileName(), e);
        }
    }

    @Override
    public String toString() {
        return "SignatureMetadata{"
                + "version='" + formatVersion + '\''
                + ", algorithm='" + signatureAlgorithm + '\''
                + ", documentFormat=" + documentFormat
                + ", documentDigest='" + documentDigest + '\''
                + ", publicKeyId='" + publicKeyId + '\''
                + ", signatureReference='" + signatureReference + '\''
                + ", createdAt=" + createdAt
                + '}';
    }
}
