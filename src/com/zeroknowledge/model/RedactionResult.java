package com.zeroknowledge.model;

import com.zeroknowledge.document.DocumentFormat;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents the outcome of applying user-approved redactions to a document.
 */
public final class RedactionResult {

    private final boolean success;
    private final DocumentFormat format;
    private final Path sourcePath;
    private final Path outputPath;
    private final String sourceSha256;
    private final String outputSha256;
    private final int totalCandidatesConsidered;
    private final int approvedMatchesApplied;
    private final List<RedactionMatch> appliedMatches;
    private final Instant timestamp;
    private final String summaryMessage;

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
        this.success = success;
        this.format = Objects.requireNonNull(format, "format must not be null");
        this.sourcePath = sourcePath;
        this.outputPath = outputPath;
        this.sourceSha256 = sourceSha256;
        this.outputSha256 = outputSha256;
        this.totalCandidatesConsidered = totalCandidatesConsidered;
        this.approvedMatchesApplied = approvedMatchesApplied;
        this.appliedMatches = appliedMatches == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(appliedMatches));
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null");
        this.summaryMessage = Objects.requireNonNull(summaryMessage, "summaryMessage must not be null");
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

    public int getApprovedMatchesApplied() {
        return approvedMatchesApplied;
    }

    public List<RedactionMatch> getAppliedMatches() {
        return appliedMatches;
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
                + ", format=" + format
                + ", outputPath=" + (outputPath != null ? outputPath.getFileName() : "none")
                + ", outputSha256='" + outputSha256 + '\''
                + ", approvedMatchesApplied=" + approvedMatchesApplied
                + ", summaryMessage='" + summaryMessage + '\''
                + '}';
    }
}
