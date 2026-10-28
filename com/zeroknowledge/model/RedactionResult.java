package com.zeroknowledge.model;

import java.io.File;

/**
 * Result of a document redaction operation.
 */
public class RedactionResult {
    private final boolean success;
    private final String originalFilePath;
    private final String outputFilePath;
    private final int totalCandidatesFound;
    private final int candidatesRedacted;
    private final String originalFileSha256;
    private final String redactedFileSha256;
    private final boolean signed;
    private final String signaturePath;
    private final String errorMessage;

    public RedactionResult(boolean success, String originalFilePath, String outputFilePath,
                           int totalCandidatesFound, int candidatesRedacted,
                           String originalFileSha256, String redactedFileSha256,
                           boolean signed, String signaturePath, String errorMessage) {
        this.success = success;
        this.originalFilePath = originalFilePath;
        this.outputFilePath = outputFilePath;
        this.totalCandidatesFound = totalCandidatesFound;
        this.candidatesRedacted = candidatesRedacted;
        this.originalFileSha256 = originalFileSha256;
        this.redactedFileSha256 = redactedFileSha256;
        this.signed = signed;
        this.signaturePath = signaturePath;
        this.errorMessage = errorMessage;
    }

    public static RedactionResult failure(String originalFilePath, String errorMessage) {
        return new RedactionResult(false, originalFilePath, null, 0, 0, null, null, false, null, errorMessage);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getOriginalFilePath() {
        return originalFilePath;
    }

    public String getOutputFilePath() {
        return outputFilePath;
    }

    public int getTotalCandidatesFound() {
        return totalCandidatesFound;
    }

    public int getCandidatesRedacted() {
        return candidatesRedacted;
    }

    public String getOriginalFileSha256() {
        return originalFileSha256;
    }

    public String getRedactedFileSha256() {
        return redactedFileSha256;
    }

    public boolean isSigned() {
        return signed;
    }

    public String getSignaturePath() {
        return signaturePath;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getOutputFileName() {
        if (outputFilePath == null) return "";
        return new File(outputFilePath).getName();
    }
}
