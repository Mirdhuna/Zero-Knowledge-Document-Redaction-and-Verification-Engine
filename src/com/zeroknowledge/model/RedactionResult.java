package com.zeroknowledge.model;

import com.zeroknowledge.document.DocumentFormat;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents the outcome of applying user-approved redactions to a document,
 * including independent post-redaction verification status and detailed metrics.
 */
public final class RedactionResult {

    /**
     * Explicit post-redaction verification outcomes (Stage 5).
     */
    public enum VerificationStatus {
        /** All selected redactions passed independent text and image verification checks. */
        VERIFIED,
        /** Some redactions succeeded, but one or more candidates were skipped, required manual review, or failed. */
        PARTIAL,
        /** The output could not be safely verified or sensitive content remained detectable. */
        FAILED
    }

    public static final String VERIFICATION_DISCLAIMER =
            "Automated post-redaction checks verify extracted text streams and rendered pixel regions to substantially reduce risk, "
            + "but cannot mathematically prove the absence of every possible contextual or semantic disclosure.";

    private final boolean success;
    private final DocumentFormat format;
    private final Path sourcePath;
    private final Path outputPath;
    private final String sourceSha256;
    private final String outputSha256;
    private final int totalCandidatesConsidered;
    private final int selectedMatchesCount;
    private final int approvedMatchesApplied;
    private final int skippedMatchesCount;
    private final int failedMatchesCount;
    private final List<RedactionMatch> appliedMatches;
    private final VerificationStatus verificationStatus;
    private final String verificationReport;
    private final List<String> verificationWarnings;
    private final Instant timestamp;
    private final String summaryMessage;

    /**
     * Full constructor with detailed counts and independent post-redaction verification outcome.
     */
    public RedactionResult(
            boolean success,
            DocumentFormat format,
            Path sourcePath,
            Path outputPath,
            String sourceSha256,
            String outputSha256,
            int totalCandidatesConsidered,
            int selectedMatchesCount,
            int approvedMatchesApplied,
            int skippedMatchesCount,
            int failedMatchesCount,
            List<RedactionMatch> appliedMatches,
            VerificationStatus verificationStatus,
            String verificationReport,
            List<String> verificationWarnings,
            Instant timestamp,
            String summaryMessage) {
        this.success = success;
        this.format = Objects.requireNonNull(format, "format must not be null");
        this.sourcePath = sourcePath;
        this.outputPath = outputPath;
        this.sourceSha256 = sourceSha256;
        this.outputSha256 = outputSha256;
        this.totalCandidatesConsidered = Math.max(0, totalCandidatesConsidered);
        this.selectedMatchesCount = Math.max(0, selectedMatchesCount);
        this.approvedMatchesApplied = Math.max(0, approvedMatchesApplied);
        this.skippedMatchesCount = Math.max(0, skippedMatchesCount);
        this.failedMatchesCount = Math.max(0, failedMatchesCount);
        this.appliedMatches = appliedMatches == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(appliedMatches));
        this.verificationStatus = Objects.requireNonNull(verificationStatus, "verificationStatus must not be null");
        this.verificationReport = verificationReport == null ? VERIFICATION_DISCLAIMER : verificationReport;
        this.verificationWarnings = verificationWarnings == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(verificationWarnings));
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null");
        this.summaryMessage = Objects.requireNonNull(summaryMessage, "summaryMessage must not be null");
    }

    /**
     * Backward-compatible 11-argument constructor.
     */
    public RedactionResult(
            boolean success,
            DocumentFormat format,
            Path sourcePath,
            Path outputPath,
            String sourceSha256,
            String outputSha256,
            int totalCandidatesConsidered,
            int approvedMatchesApplied,
            List<RedactionMatch> appliedMatches,
            Instant timestamp,
            String summaryMessage) {
        this(
                success,
                format,
                sourcePath,
                outputPath,
                sourceSha256,
                outputSha256,
                totalCandidatesConsidered,
                approvedMatchesApplied,
                approvedMatchesApplied,
                Math.max(0, totalCandidatesConsidered - approvedMatchesApplied),
                success ? 0 : Math.max(1, totalCandidatesConsidered - approvedMatchesApplied),
                appliedMatches,
                !success
                        ? VerificationStatus.FAILED
                        : (totalCandidatesConsidered > approvedMatchesApplied && approvedMatchesApplied > 0
                                ? VerificationStatus.PARTIAL
                                : VerificationStatus.VERIFIED),
                VERIFICATION_DISCLAIMER,
                List.of(),
                timestamp,
                summaryMessage);
    }

    public boolean isSuccess() {
        return success;
    }

    public DocumentFormat getFormat() {
        return format;
    }

    public Path getSourcePath() {
        return sourcePath;
    }

    public Path getOutputPath() {
        return outputPath;
    }

    public String getSourceSha256() {
        return sourceSha256;
    }

    public String getOutputSha256() {
        return outputSha256;
    }

    public int getTotalCandidatesConsidered() {
        return totalCandidatesConsidered;
    }

    public int getSelectedMatchesCount() {
        return selectedMatchesCount;
    }

    public int getApprovedMatchesApplied() {
        return approvedMatchesApplied;
    }

    public int getSkippedMatchesCount() {
        return skippedMatchesCount;
    }

    public int getFailedMatchesCount() {
        return failedMatchesCount;
    }

    public List<RedactionMatch> getAppliedMatches() {
        return appliedMatches;
    }

    public VerificationStatus getVerificationStatus() {
        return verificationStatus;
    }

    public String getVerificationReport() {
        return verificationReport;
    }

    public List<String> getVerificationWarnings() {
        return verificationWarnings;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSummaryMessage() {
        return summaryMessage;
    }

    @Override
    public String toString() {
        return "RedactionResult{"
                + "success=" + success
                + ", verificationStatus=" + verificationStatus
                + ", format=" + format
                + ", outputPath=" + (outputPath != null ? outputPath.getFileName() : "none")
                + ", outputSha256='" + outputSha256 + '\''
                + ", detected=" + totalCandidatesConsidered
                + ", applied=" + approvedMatchesApplied
                + ", skipped=" + skippedMatchesCount
                + ", failed=" + failedMatchesCount
                + ", summaryMessage='" + summaryMessage + '\''
                + '}';
    }
}
