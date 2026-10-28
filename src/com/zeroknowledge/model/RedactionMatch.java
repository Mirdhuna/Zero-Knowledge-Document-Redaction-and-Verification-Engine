package com.zeroknowledge.model;

import java.util.Objects;

/**
 * Represents a heuristic sensitive-data candidate detected in a document.
 *
 * <p>Security Design Note:
 * Raw confidential text is intentionally excluded from {@link #toString()} and public getters
 * that might be logged. UI views use {@link #getMaskedPreview()} and location coordinates.
 */
public final class RedactionMatch implements Comparable<RedactionMatch> {

    private final String matchId;
    private final String candidateType;
    private final String ruleId;
    private final double confidence;
    private final int startOffset;
    private final int endOffset;
    private final int rowIndex;
    private final int columnIndex;
    private final String maskedPreview;
    private final String replacementToken;
    private boolean selectedForRedaction;

    /**
     * Constructs a RedactionMatch for a plain-text or cell-specific match.
     *
     * @param matchId              unique identifier for this candidate within a scan
     * @param candidateType        category name (e.g., "EMAIL", "PHONE", "SSN", "CREDIT_CARD")
     * @param ruleId               identifier of the regex rule that matched
     * @param confidence           heuristic confidence score in [0.0, 1.0]
     * @param startOffset          0-based inclusive character offset (within document for TXT, or within cell for CSV)
     * @param endOffset            0-based exclusive character offset (within document for TXT, or within cell for CSV)
     * @param rowIndex             0-based CSV row index, or -1 for plain text
     * @param columnIndex          0-based CSV column index, or -1 for plain text
     * @param maskedPreview        privacy-safe masked preview (e.g. "j***e@example.com")
     * @param replacementToken     marker to substitute when approved (e.g. "[REDACTED_EMAIL]")
     * @param selectedForRedaction whether approved/selected by the user
     */
    public RedactionMatch(
            String matchId,
            String candidateType,
            String ruleId,
            double confidence,
            int startOffset,
            int endOffset,
            int rowIndex,
            int columnIndex,
            String maskedPreview,
            String replacementToken,
            boolean selectedForRedaction) {
        if (startOffset < 0 || endOffset < startOffset) {
            throw new IllegalArgumentException("Invalid character offsets: start=" + startOffset + ", end=" + endOffset);
        }
        if (confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException("Confidence must be between 0.0 and 1.0");
        }
        this.matchId = Objects.requireNonNull(matchId, "matchId must not be null");
        this.candidateType = Objects.requireNonNull(candidateType, "candidateType must not be null");
        this.ruleId = Objects.requireNonNull(ruleId, "ruleId must not be null");
        this.confidence = confidence;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
        this.rowIndex = rowIndex;
        this.columnIndex = columnIndex;
        this.maskedPreview = Objects.requireNonNull(maskedPreview, "maskedPreview must not be null");
        this.replacementToken = Objects.requireNonNull(replacementToken, "replacementToken must not be null");
        this.selectedForRedaction = selectedForRedaction;
    }

    /**
     * Convenience constructor for plain text matches (rowIndex = -1, columnIndex = -1).
     */
    public RedactionMatch(
            String matchId,
            String candidateType,
            String ruleId,
            double confidence,
            int startOffset,
            int endOffset,
            String maskedPreview,
            String replacementToken,
            boolean selectedForRedaction) {
        this(
                matchId,
                candidateType,
                ruleId,
                confidence,
                startOffset,
                endOffset,
                -1,
                -1,
                maskedPreview,
                replacementToken,
                selectedForRedaction);
    }

    public String getMatchId() {
        return matchId;
    }

    public String getCandidateType() {
        return candidateType;
    }

    public String getRuleId() {
        return ruleId;
    }

    public double getConfidence() {
        return confidence;
    }

    public int getStartOffset() {
        return startOffset;
    }

    public int getEndOffset() {
        return endOffset;
    }

    public int getLength() {
        return endOffset - startOffset;
    }

    public int getRowIndex() {
        return rowIndex;
    }

    public int getColumnIndex() {
        return columnIndex;
    }

    public boolean isCellScoped() {
        return rowIndex >= 0 && columnIndex >= 0;
    }

    public String getMaskedPreview() {
        return maskedPreview;
    }

    public String getReplacementToken() {
        return replacementToken;
    }

    public boolean isSelectedForRedaction() {
        return selectedForRedaction;
    }

    public void setSelectedForRedaction(boolean selectedForRedaction) {
        this.selectedForRedaction = selectedForRedaction;
    }

    /**
     * Returns a copy of this match with the specified selection state.
     */
    public RedactionMatch withSelection(boolean selected) {
        return new RedactionMatch(
                matchId,
                candidateType,
                ruleId,
                confidence,
                startOffset,
                endOffset,
                rowIndex,
                columnIndex,
                maskedPreview,
                replacementToken,
                selected);
    }

    /**
     * Utility method to create a privacy-preserving masked preview of a sensitive string.
     */
    public static String maskValue(String rawValue) {
        if (rawValue == null || rawValue.isEmpty()) {
            return "***";
        }
        int len = rawValue.length();
        if (len <= 2) {
            return "*".repeat(len);
        }
        if (len <= 6) {
            return rawValue.charAt(0) + "*".repeat(len - 2) + rawValue.charAt(len - 1);
        }
        int atIndex = rawValue.indexOf('@');
        if (atIndex > 1 && atIndex < len - 1) {
            String local = rawValue.substring(0, atIndex);
            String domain = rawValue.substring(atIndex);
            String maskedLocal = local.charAt(0) + "***" + (local.length() > 2 ? local.charAt(local.length() - 1) : "");
            return maskedLocal + domain;
        }
        return rawValue.substring(0, 2) + "*".repeat(Math.min(6, len - 4)) + rawValue.substring(len - 2);
    }

    @Override
    public int compareTo(RedactionMatch other) {
        int rowCmp = Integer.compare(this.rowIndex, other.rowIndex);
        if (rowCmp != 0) {
            return rowCmp;
        }
        int colCmp = Integer.compare(this.columnIndex, other.columnIndex);
        if (colCmp != 0) {
            return colCmp;
        }
        int startCmp = Integer.compare(this.startOffset, other.startOffset);
        if (startCmp != 0) {
            return startCmp;
        }
        return Integer.compare(other.endOffset, this.endOffset);
    }

    @Override
    public String toString() {
        return "RedactionMatch{"
                + "id='" + matchId + '\''
                + ", type='" + candidateType + '\''
                + ", rule='" + ruleId + '\''
                + ", row=" + rowIndex
                + ", col=" + columnIndex
                + ", range=[" + startOffset + "," + endOffset + ")"
                + ", preview='" + maskedPreview + '\''
                + ", selected=" + selectedForRedaction
                + '}';
    }
}
