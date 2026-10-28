package com.zeroknowledge.model;

/**
 * Result of a document and detached digital signature verification operation.
 */
public class VerificationResult {

    public enum Status {
        SIGNATURE_VALID("Signature Valid", true),
        VERIFICATION_FAILED("Verification Failed", false),
        DOCUMENT_MODIFIED_OR_MISMATCH("Document Modified or Signature Mismatch", false),
        SIGNATURE_MISSING_OR_INVALID("Signature Missing or Invalid", false),
        TRUSTED_PUBLIC_KEY_UNAVAILABLE("Trusted Public Key Unavailable", false),
        UNSUPPORTED_OPERATION("Unsupported Operation", false),
        VERIFICATION_ERROR("Verification Error", false);

        private final String displayName;
        private final boolean valid;

        Status(String displayName, boolean valid) {
            this.displayName = displayName;
            this.valid = valid;
        }

        public String getDisplayName() {
            return displayName;
        }

        public boolean isValid() {
            return valid;
        }
    }

    private final Status status;
    private final String documentPath;
    private final String signaturePath;
    private final String keyFingerprint;
    private final String keyAlgorithm;
    private final String computedSha256;
    private final String detailedMessage;
    private final long verificationDurationMs;

    public VerificationResult(Status status, String documentPath, String signaturePath,
                              String keyFingerprint, String keyAlgorithm,
                              String computedSha256, String detailedMessage,
                              long verificationDurationMs) {
        this.status = status;
        this.documentPath = documentPath;
        this.signaturePath = signaturePath;
        this.keyFingerprint = keyFingerprint;
        this.keyAlgorithm = keyAlgorithm;
        this.computedSha256 = computedSha256;
        this.detailedMessage = detailedMessage;
        this.verificationDurationMs = verificationDurationMs;
    }

    public static VerificationResult create(Status status, String documentPath, String signaturePath,
                                            String keyFingerprint, String keyAlgorithm,
                                            String computedSha256, String detailedMessage,
                                            long verificationDurationMs) {
        return new VerificationResult(status, documentPath, signaturePath, keyFingerprint,
                keyAlgorithm, computedSha256, detailedMessage, verificationDurationMs);
    }

    public Status getStatus() {
        return status;
    }

    public boolean isValid() {
        return status != null && status.isValid();
    }

    public String getDocumentPath() {
        return documentPath;
    }

    public String getSignaturePath() {
        return signaturePath;
    }

    public String getKeyFingerprint() {
        return keyFingerprint;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getComputedSha256() {
        return computedSha256;
    }

    public String getDetailedMessage() {
        return detailedMessage;
    }

    public long getVerificationDurationMs() {
        return verificationDurationMs;
    }
}
