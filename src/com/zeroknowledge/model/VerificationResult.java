package com.zeroknowledge.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Structured outcome of verifying a document against a detached digital signature and public key.
 */
public final class VerificationResult {

    /**
     * Explicit verification status categories required to distinguish cryptographic outcomes.
     */
    public enum Status {
        /** Signature is cryptographically valid for the exact document bytes using the trusted public key. */
        VALID_SIGNATURE,
        /** Cryptographic signature check failed or document bytes do not match signed content. */
        SIGNATURE_MISMATCH_OR_MODIFIED,
        /** Detached signature file or metadata file is missing. */
        MISSING_SIGNATURE_OR_METADATA,
        /** Detached signature or metadata file has corrupt/invalid encoding or unsupported version. */
        INVALID_SIGNATURE_ENCODING,
        /** Public key is missing, unreadable, invalid, or does not match the expected trusted key identifier. */
        MISSING_OR_UNTRUSTED_PUBLIC_KEY,
        /** Requested operation is unsupported for this document type or state. */
        UNSUPPORTED_OPERATION,
        /** General I/O or system processing error occurred during verification. */
        PROCESSING_FAILURE
    }

    private final Status status;
    private final boolean verified;
    private final String userSafeExplanation;
    private final String technicalDetails;
    private final String calculatedDocumentDigest;
    private final String publicKeyId;
    private final Instant verifiedAt;

    public VerificationResult(
            Status status,
            String userSafeExplanation,
            String technicalDetails,
            String calculatedDocumentDigest,
            String publicKeyId,
            Instant verifiedAt) {
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.verified = (status == Status.VALID_SIGNATURE);
        this.userSafeExplanation = Objects.requireNonNull(userSafeExplanation, "userSafeExplanation must not be null");
        this.technicalDetails = technicalDetails == null ? "" : technicalDetails;
        this.calculatedDocumentDigest = calculatedDocumentDigest == null ? "" : calculatedDocumentDigest;
        this.publicKeyId = publicKeyId == null ? "" : publicKeyId;
        this.verifiedAt = Objects.requireNonNull(verifiedAt, "verifiedAt must not be null");
    }

    public Status getStatus() {
        return status;
    }

    public boolean isVerified() {
        return verified;
    }

    public String getUserSafeExplanation() {
        return userSafeExplanation;
    }

    public String getTechnicalDetails() {
        return technicalDetails;
    }

    public String getCalculatedDocumentDigest() {
        return calculatedDocumentDigest;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }

    public Instant getVerifiedAt() {
        return verifiedAt;
    }

    @Override
    public String toString() {
        return "VerificationResult{"
                + "status=" + status
                + ", verified=" + verified
                + ", explanation='" + userSafeExplanation + '\''
                + ", digest='" + calculatedDocumentDigest + '\''
                + ", keyId='" + publicKeyId + '\''
                + ", verifiedAt=" + verifiedAt
                + '}';
    }
}
