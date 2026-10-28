package com.zeroknowledge.backend;

import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.crypto.KeyManager;
import com.zeroknowledge.crypto.SignatureMetadata;
import com.zeroknowledge.crypto.SignatureService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.KeyManagementException;
import com.zeroknowledge.exception.SignatureVerificationException;
import com.zeroknowledge.model.OperationRecord.OperationType;
import com.zeroknowledge.model.VerificationResult;
import com.zeroknowledge.model.VerificationResult.Status;
import com.zeroknowledge.storage.AuditService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * High-level verification service that verifies a document against a detached {@link SignatureMetadata}
 * file and an explicitly trusted {@link PublicKey}.
 *
 * <h3>Security Guarantees</h3>
 * <ul>
 *   <li>Never trusts a sidecar SHA-256 digest alone as proof of authenticity.</li>
 *   <li>Requires an explicitly supplied or loaded {@link PublicKey} representing the user's trust decision.</li>
 *   <li>Distinguishes all 7 required verification outcomes in {@link VerificationResult.Status}.</li>
 * </ul>
 */
public final class VerificationService {

    private final HashService hashService;
    private final KeyManager keyManager;
    private final SignatureService signatureService;
    private final AccessControlService accessControlService;
    private final AuditService auditService;

    public VerificationService(
            HashService hashService,
            KeyManager keyManager,
            SignatureService signatureService,
            AccessControlService accessControlService,
            AuditService auditService) {
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
        this.keyManager = Objects.requireNonNull(keyManager, "keyManager must not be null");
        this.signatureService = Objects.requireNonNull(signatureService, "signatureService must not be null");
        this.accessControlService = Objects.requireNonNull(accessControlService, "accessControlService must not be null");
        this.auditService = Objects.requireNonNull(auditService, "auditService must not be null");
    }

    public VerificationService() {
        this.hashService = new HashService();
        this.keyManager = new KeyManager(hashService);
        this.signatureService = new SignatureService(hashService, keyManager);
        this.auditService = new AuditService();
        this.accessControlService = new AccessControlService(AccessControlService.Role.SECURITY_ADMINISTRATOR, auditService);
    }

    /**
     * Verifies a document using a detached signature file and a public key file on disk.
     */
    public VerificationResult verifyDocument(
            Path documentPath,
            Path signaturePath,
            Path trustedPublicKeyPath) {
        accessControlService.requirePermission(AccessControlService.Permission.VERIFY_SIGNATURE);

        String docName = (documentPath != null && documentPath.getFileName() != null)
                ? documentPath.getFileName().toString()
                : "unknown";

        if (trustedPublicKeyPath == null) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                    "Verification failed: no trusted public key path was provided.",
                    "trustedPublicKeyPath == null",
                    "",
                    "");
        }

        Path normKeyPath = trustedPublicKeyPath.toAbsolutePath().normalize();
        if (!Files.exists(normKeyPath) || !Files.isRegularFile(normKeyPath)) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                    "Verification failed: the specified public key file does not exist.",
                    "Missing key file: " + normKeyPath.getFileName(),
                    "",
                    "");
        }

        PublicKey trustedKey;
        try {
            trustedKey = keyManager.loadPublicKey(normKeyPath);
        } catch (KeyManagementException e) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                    "Verification failed: the public key file is invalid or uses an unsupported key format.",
                    e.getMessage(),
                    "",
                    "");
        }

        return verifyDocument(documentPath, signaturePath, trustedKey);
    }

    /**
     * Verifies a document using a detached signature file and an in-memory trusted {@link PublicKey}.
     */
    public VerificationResult verifyDocument(
            Path documentPath,
            Path signaturePath,
            PublicKey trustedPublicKey) {
        accessControlService.requirePermission(AccessControlService.Permission.VERIFY_SIGNATURE);

        String docName = (documentPath != null && documentPath.getFileName() != null)
                ? documentPath.getFileName().toString()
                : "unknown";

        // 1. Validate trusted public key
        if (trustedPublicKey == null) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                    "Verification failed: no trusted public key was provided.",
                    "trustedPublicKey == null",
                    "",
                    "");
        }

        String trustedKeyId;
        try {
            keyManager.validatePublicKey(trustedPublicKey);
            trustedKeyId = keyManager.getKeyIdentifier(trustedPublicKey);
        } catch (KeyManagementException e) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                    "Verification failed: the supplied public key is invalid or too weak.",
                    e.getMessage(),
                    "",
                    "");
        }

        // 2. Validate document path and format support
        if (documentPath == null) {
            return recordAndReturn(
                    docName,
                    Status.PROCESSING_FAILURE,
                    "Verification failed: document path is null.",
                    "documentPath == null",
                    "",
                    trustedKeyId);
        }

        Path normDoc = documentPath.toAbsolutePath().normalize();
        if (!Files.exists(normDoc) || !Files.isRegularFile(normDoc) || !Files.isReadable(normDoc)) {
            return recordAndReturn(
                    docName,
                    Status.PROCESSING_FAILURE,
                    "Verification failed: the target document does not exist or cannot be read.",
                    "Unreadable or missing document: " + normDoc.getFileName(),
                    "",
                    trustedKeyId);
        }

        DocumentFormat docFormat = DocumentFormat.fromPath(normDoc);
        if (!docFormat.isSigningAndVerificationSupported()) {
            return recordAndReturn(
                    docName,
                    Status.UNSUPPORTED_OPERATION,
                    "Verification failed: the selected file format is not supported for verification.",
                    "Unsupported format for file: " + normDoc.getFileName(),
                    "",
                    trustedKeyId);
        }

        // 3. Calculate actual SHA-256 digest of the document bytes on disk
        String actualDigest;
        try {
            actualDigest = hashService.calculateSha256(normDoc);
        } catch (DocumentProcessingException e) {
            return recordAndReturn(
                    docName,
                    Status.PROCESSING_FAILURE,
                    "Verification failed: unable to read and hash document bytes.",
                    e.getMessage(),
                    "",
                    trustedKeyId);
        }

        // 4. Check signature metadata existence
        if (signaturePath == null) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_SIGNATURE_OR_METADATA,
                    "Verification failed: detached signature path was not provided.",
                    "signaturePath == null",
                    actualDigest,
                    trustedKeyId);
        }

        Path normSig = signaturePath.toAbsolutePath().normalize();
        if (!Files.exists(normSig) || !Files.isRegularFile(normSig)) {
            return recordAndReturn(
                    docName,
                    Status.MISSING_SIGNATURE_OR_METADATA,
                    "Verification failed: the detached signature file is missing.",
                    "Missing signature file: " + normSig.getFileName(),
                    actualDigest,
                    trustedKeyId);
        }

        // 5. Parse and validate signature metadata encoding
        SignatureMetadata metadata;
        byte[] signatureBytes;
        try {
            metadata = SignatureMetadata.loadFromFile(normSig);
            signatureBytes = metadata.getSignatureBytes();
        } catch (SignatureVerificationException e) {
            return recordAndReturn(
                    docName,
                    Status.INVALID_SIGNATURE_ENCODING,
                    "Verification failed: the detached signature or metadata file is malformed or corrupted.",
                    e.getMessage(),
                    actualDigest,
                    trustedKeyId);
        }

        // 6. Verify that the metadata's key ID matches the explicitly trusted public key
        if (!trustedKeyId.equals(metadata.getPublicKeyId())) {
            // Also check if the raw cryptographic signature matches the trusted key anyway or if it was signed by a different key
            try {
                boolean rawMatch = signatureService.verifyFileBytes(normDoc, signatureBytes, trustedPublicKey);
                if (!rawMatch) {
                    return recordAndReturn(
                            docName,
                            Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                            "Verification failed: the signature was created by a different key ("
                                    + metadata.getPublicKeyId() + ") than the trusted public key (" + trustedKeyId + ").",
                            "Key ID mismatch and cryptographic signature rejected by trusted key",
                            actualDigest,
                            trustedKeyId);
                }
            } catch (SignatureVerificationException e) {
                return recordAndReturn(
                        docName,
                        Status.INVALID_SIGNATURE_ENCODING,
                        "Verification failed: invalid cryptographic signature structure.",
                        e.getMessage(),
                        actualDigest,
                        trustedKeyId);
            }
            return recordAndReturn(
                    docName,
                    Status.SIGNATURE_MISMATCH_OR_MODIFIED,
                    "Verification failed: signature metadata key identifier does not match the trusted key.",
                    "Metadata keyId=" + metadata.getPublicKeyId() + ", trustedKeyId=" + trustedKeyId,
                    actualDigest,
                    trustedKeyId);
        }

        // 7. Cryptographically verify the RSA signature over the exact bytes of the document
        boolean cryptoValid;
        try {
            cryptoValid = signatureService.verifyFileBytes(normDoc, signatureBytes, trustedPublicKey);
        } catch (SignatureVerificationException e) {
            return recordAndReturn(
                    docName,
                    Status.INVALID_SIGNATURE_ENCODING,
                    "Verification failed: signature bytes could not be processed by SHA256withRSA.",
                    e.getMessage(),
                    actualDigest,
                    trustedKeyId);
        }

        if (!cryptoValid) {
            return recordAndReturn(
                    docName,
                    Status.SIGNATURE_MISMATCH_OR_MODIFIED,
                    "Verification failed: the document has been modified since signing, or the signature does not match.",
                    "SHA256withRSA verification returned false; actualDigest=" + actualDigest
                            + ", metadataDigest=" + metadata.getDocumentDigest(),
                    actualDigest,
                    trustedKeyId);
        }

        // 8. Also ensure metadata digest matches actual digest (prevents inconsistent sidecar metadata)
        if (!actualDigest.equalsIgnoreCase(metadata.getDocumentDigest())) {
            return recordAndReturn(
                    docName,
                    Status.SIGNATURE_MISMATCH_OR_MODIFIED,
                    "Verification failed: metadata SHA-256 digest does not match the actual document digest.",
                    "Metadata digest mismatch despite signature check",
                    actualDigest,
                    trustedKeyId);
        }

        return recordAndReturn(
                docName,
                Status.VALID_SIGNATURE,
                "Authentic document: SHA256withRSA digital signature and SHA-256 digest verified against trusted key "
                        + trustedKeyId + ".",
                "Format=" + metadata.getFormatVersion() + ", signedAt=" + metadata.getCreatedAt(),
                actualDigest,
                trustedKeyId);
    }

    private VerificationResult recordAndReturn(
            String docName,
            Status status,
            String explanation,
            String technicalDetails,
            String digest,
            String keyId) {
        boolean ok = (status == Status.VALID_SIGNATURE);
        auditService.record(
                OperationType.SIGNATURE_VERIFY,
                docName,
                ok,
                "Status=" + status.name() + ", keyId=" + (keyId.isEmpty() ? "N/A" : keyId));
        return new VerificationResult(
                status,
                explanation,
                technicalDetails,
                digest,
                keyId,
                Instant.now());
    }
}
