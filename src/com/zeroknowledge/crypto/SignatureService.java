package com.zeroknowledge.crypto;

import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.KeyManagementException;
import com.zeroknowledge.exception.SignatureVerificationException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * Cryptographic digital signature service using {@code SHA256withRSA}.
 *
 * <p>Operates on the exact bytes of a saved artifact on disk via streaming I/O.
 * Never trusts metadata digests without verifying the RSA signature directly against
 * the file's actual byte stream and an explicitly supplied {@link PublicKey}.
 */
public final class SignatureService {

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int STREAM_BUFFER_SIZE = 64 * 1024; // 64 KB chunks

    private final HashService hashService;
    private final KeyManager keyManager;

    public SignatureService(HashService hashService, KeyManager keyManager) {
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
        this.keyManager = Objects.requireNonNull(keyManager, "keyManager must not be null");
    }

    public SignatureService() {
        this(new HashService(), new KeyManager());
    }

    /**
     * Signs the exact bytes of a file using {@code SHA256withRSA} and returns the raw signature bytes.
     *
     * @param documentPath path to the saved document artifact
     * @param privateKey   authorized RSA private key
     * @return raw RSA signature bytes
     * @throws SignatureVerificationException if the key is invalid, file cannot be read, or signing fails
     */
    public byte[] signFileBytes(Path documentPath, PrivateKey privateKey) throws SignatureVerificationException {
        Objects.requireNonNull(documentPath, "documentPath must not be null");
        try {
            keyManager.validatePrivateKey(privateKey);
        } catch (KeyManagementException e) {
            throw new SignatureVerificationException("Invalid private key for signing: " + e.getMessage(), e);
        }

        Path normalized = validateReadableFile(documentPath);
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);

            byte[] buffer = new byte[STREAM_BUFFER_SIZE];
            try (InputStream in = Files.newInputStream(normalized)) {
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    signature.update(buffer, 0, bytesRead);
                }
            }
            return signature.sign();
        } catch (GeneralSecurityException | IOException e) {
            throw new SignatureVerificationException(
                    "Failed to compute SHA256withRSA signature for file: " + normalized.getFileName(), e);
        }
    }

    /**
     * Signs a saved artifact and writes a detached {@link SignatureMetadata} bundle to {@code signatureOutputPath}.
     *
     * @param documentPath        path to the saved document artifact
     * @param privateKey          authorized RSA private key
     * @param publicKey           corresponding RSA public key (to record the key identifier)
     * @param signatureOutputPath path where the detached signature metadata file should be written
     * @return created {@link SignatureMetadata}
     * @throws SignatureVerificationException if signing or saving fails
     */
    public SignatureMetadata signAndSaveDetached(
            Path documentPath,
            PrivateKey privateKey,
            PublicKey publicKey,
            Path signatureOutputPath) throws SignatureVerificationException {
        Objects.requireNonNull(documentPath, "documentPath must not be null");
        Objects.requireNonNull(signatureOutputPath, "signatureOutputPath must not be null");

        Path normalizedDoc = validateReadableFile(documentPath);
        Path normalizedSig = signatureOutputPath.toAbsolutePath().normalize();
        if (normalizedDoc.equals(normalizedSig)) {
            throw new SignatureVerificationException("Signature output path must not overwrite the document path");
        }

        DocumentFormat format = DocumentFormat.fromPath(normalizedDoc);
        if (format == DocumentFormat.UNSUPPORTED) {
            throw new SignatureVerificationException(
                    "Cannot sign unsupported document format: " + normalizedDoc.getFileName());
        }

        String keyId;
        try {
            keyId = keyManager.getKeyIdentifier(publicKey);
        } catch (KeyManagementException e) {
            throw new SignatureVerificationException("Invalid public key for metadata: " + e.getMessage(), e);
        }

        String digest;
        try {
            digest = hashService.calculateSha256(normalizedDoc);
        } catch (DocumentProcessingException e) {
            throw new SignatureVerificationException("Failed to hash document during signing", e);
        }

        byte[] rawSignature = signFileBytes(normalizedDoc, privateKey);

        // Verify that the provided PublicKey actually corresponds to the PrivateKey used to sign
        boolean pairMatches = verifyFileBytes(normalizedDoc, rawSignature, publicKey);
        if (!pairMatches) {
            throw new SignatureVerificationException(
                    "Provided public key does not correspond to the signing private key");
        }

        String sigBase64 = Base64.getEncoder().encodeToString(rawSignature);
        SignatureMetadata metadata = new SignatureMetadata(
                SignatureMetadata.CURRENT_FORMAT_VERSION,
                SIGNATURE_ALGORITHM,
                format,
                digest,
                keyId,
                normalizedSig.getFileName().toString(),
                Instant.now(),
                sigBase64);

        metadata.saveToFile(normalizedSig);
        return metadata;
    }

    /**
     * Loads a detached {@link SignatureMetadata} bundle from disk.
     */
    public SignatureMetadata loadDetachedSignature(Path signaturePath) throws SignatureVerificationException {
        return SignatureMetadata.loadFromFile(signaturePath);
    }

    /**
     * Cryptographically verifies raw signature bytes against the exact bytes of {@code documentPath}
     * and an explicitly trusted {@link PublicKey} using streaming I/O.
     *
     * @param documentPath   path to the document to verify
     * @param signatureBytes raw RSA signature bytes
     * @param trustedKey     trusted RSA public key
     * @return {@code true} if and only if the cryptographic signature is valid for the exact file bytes
     * @throws SignatureVerificationException if the key is invalid, signature encoding is malformed, or I/O fails
     */
    public boolean verifyFileBytes(Path documentPath, byte[] signatureBytes, PublicKey trustedKey)
            throws SignatureVerificationException {
        Objects.requireNonNull(documentPath, "documentPath must not be null");
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new SignatureVerificationException("Signature bytes are empty");
        }
        try {
            keyManager.validatePublicKey(trustedKey);
        } catch (KeyManagementException e) {
            throw new SignatureVerificationException("Invalid or untrusted public key: " + e.getMessage(), e);
        }

        Path normalized = validateReadableFile(documentPath);
        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(trustedKey);

            byte[] buffer = new byte[STREAM_BUFFER_SIZE];
            try (InputStream in = Files.newInputStream(normalized)) {
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    verifier.update(buffer, 0, bytesRead);
                }
            }
            return verifier.verify(signatureBytes);
        } catch (SignatureException e) {
            // Malformed ASN.1 / RSA signature block length or padding error
            return false;
        } catch (GeneralSecurityException | IOException e) {
            throw new SignatureVerificationException(
                    "Error while verifying signature for file: " + normalized.getFileName(), e);
        }
    }

    /**
     * Verifies a detached {@link SignatureMetadata} file against a document and trusted {@link PublicKey}.
     * Checks both the cryptographic signature over the actual document stream and consistency with
     * the metadata's recorded key ID and SHA-256 digest.
     */
    public boolean verifyDetachedSignature(Path documentPath, Path signaturePath, PublicKey trustedKey)
            throws SignatureVerificationException {
        SignatureMetadata metadata = loadDetachedSignature(signaturePath);
        String trustedKeyId;
        try {
            trustedKeyId = keyManager.getKeyIdentifier(trustedKey);
        } catch (KeyManagementException e) {
            throw new SignatureVerificationException("Invalid trusted public key: " + e.getMessage(), e);
        }

        if (!trustedKeyId.equals(metadata.getPublicKeyId())) {
            return false;
        }

        String actualDigest;
        try {
            actualDigest = hashService.calculateSha256(documentPath);
        } catch (DocumentProcessingException e) {
            throw new SignatureVerificationException("Unable to hash document during verification", e);
        }

        if (!actualDigest.equalsIgnoreCase(metadata.getDocumentDigest())) {
            return false;
        }

        byte[] sigBytes = metadata.getSignatureBytes();
        return verifyFileBytes(documentPath, sigBytes, trustedKey);
    }

    private static Path validateReadableFile(Path path) throws SignatureVerificationException {
        Path normalized = path.toAbsolutePath().normalize();
        if (!Files.exists(normalized)) {
            throw new SignatureVerificationException("Document file does not exist: " + normalized.getFileName());
        }
        if (!Files.isRegularFile(normalized)) {
            throw new SignatureVerificationException("Document path is not a regular file: " + normalized.getFileName());
        }
        if (!Files.isReadable(normalized)) {
            throw new SignatureVerificationException("Document file is not readable: " + normalized.getFileName());
        }
        return normalized;
    }
}
