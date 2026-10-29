package com.zeroknowledge.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents a heuristic sensitive-data candidate detected in a document.
 *
 * <p>Security Design Note:
 * Raw confidential text is intentionally excluded from {@link #toString()} and public getters
 * that might be logged. UI views use {@link #getMaskedPreview()}, page number, and location coordinates.
 */
public final class RedactionMatch implements Comparable<RedactionMatch> {

    /**
     * Method by which this sensitive candidate was extracted and detected.
     */
    public enum DetectionMethod {
        NATIVE_TEXT("Native Text"),
        OCR("OCR (Scanned Image)"),
        HYBRID("Hybrid (Native + OCR)"),
        CELL_TEXT("CSV Cell");

        private final String displayName;

        DetectionMethod(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Indicates whether the candidate has reliable coordinates and confidence to be safely redacted.
     */
    public enum RedactionStatus {
        /** Coordinates and confidence are verified; can be safely and permanently redacted. */
        REDACTABLE("Redactable"),
        /** Low OCR confidence or heuristic ambiguity; user should manually review before redacting. */
        MANUAL_REVIEW_REQUIRED("Manual Review Required"),
        /** Source coordinates could not be reliably established; unsafe to claim automatic redaction. */
        UNMAPPED_UNSAFE("Unmapped (Cannot Safely Redact)");

        private final String displayName;

        RedactionStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    private final String matchId;
    private final String candidateType;
    private final String ruleId;
    private final double confidence;
    private final int startOffset;
    private final int endOffset;
    private final int rowIndex;
    private final int columnIndex;
    private final int pageNumber;
    private final DetectionMethod detectionMethod;
    private final String detectionReason;
    private final RedactionStatus redactionStatus;
    private final List<PdfBoundingBox> boundingBoxes;
    private final String maskedPreview;
    private final String replacementToken;
    private boolean selectedForRedaction;

    /**
     * Full constructor including page number, detection method, reason, redaction status, and PDF bounding boxes.
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
            int pageNumber,
            DetectionMethod detectionMethod,
            String detectionReason,
            RedactionStatus redactionStatus,
            List<PdfBoundingBox> boundingBoxes,
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
        this.pageNumber = Math.max(1, pageNumber);
        this.detectionMethod = detectionMethod != null
                ? detectionMethod
                : (rowIndex >= 0 && columnIndex >= 0 ? DetectionMethod.CELL_TEXT : DetectionMethod.NATIVE_TEXT);
        this.detectionReason = (detectionReason == null || detectionReason.isBlank())
                ? "Heuristic pattern match (" + this.ruleId + ")"
                : detectionReason.trim();
        this.redactionStatus = redactionStatus != null ? redactionStatus : RedactionStatus.REDACTABLE;
        this.boundingBoxes = boundingBoxes == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(boundingBoxes));
        this.maskedPreview = Objects.requireNonNull(maskedPreview, "maskedPreview must not be null");
        this.replacementToken = Objects.requireNonNull(replacementToken, "replacementToken must not be null");
        this.selectedForRedaction = selectedForRedaction;
    }

    /**
     * Constructs a RedactionMatch for a plain-text or cell-specific match (backward-compatible 11-arg constructor).
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
        this(
                matchId,
                candidateType,
                ruleId,
                confidence,
                startOffset,
                endOffset,
                rowIndex,
                columnIndex,
                1,
                (rowIndex >= 0 && columnIndex >= 0) ? DetectionMethod.CELL_TEXT : DetectionMethod.NATIVE_TEXT,
                "Heuristic pattern match (" + ruleId + ")",
                RedactionStatus.REDACTABLE,
                List.of(),
                maskedPreview,
                replacementToken,
                selectedForRedaction);
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

    public int getPageNumber() {
        return pageNumber;
    }

    public DetectionMethod getDetectionMethod() {
        return detectionMethod;
    }

    public String getDetectionReason() {
        return detectionReason;
    }

    public RedactionStatus getRedactionStatus() {
        return redactionStatus;
    }

    public List<PdfBoundingBox> getBoundingBoxes() {
        return boundingBoxes;
    }

    public PdfBoundingBox getPrimaryBoundingBox() {
        if (boundingBoxes.isEmpty()) {
            return null;
        }
        PdfBoundingBox unionBox = boundingBoxes.get(0);
        for (int i = 1; i < boundingBoxes.size(); i++) {
            PdfBoundingBox next = boundingBoxes.get(i);
            if (next.getPageNumber() == unionBox.getPageNumber()) {
                unionBox = unionBox.union(next);
            }
        }
        return unionBox;
    }

    public boolean canBeSafelyRedacted() {
        return redactionStatus != RedactionStatus.UNMAPPED_UNSAFE;
    }

    public boolean requiresManualReview() {
        return redactionStatus == RedactionStatus.MANUAL_REVIEW_REQUIRED
                || redactionStatus == RedactionStatus.UNMAPPED_UNSAFE
                || confidence < 0.75;
    }

    public String getFormattedLocation() {
        if (isCellScoped()) {
            return "Row " + (rowIndex + 1) + ", Col " + (columnIndex + 1);
        }
        PdfBoundingBox box = getPrimaryBoundingBox();
        if (box != null) {
            return String.format("Page %d (%.0f, %.0f, %.0fx%.0f pt)",
                    pageNumber, box.getX(), box.getY(), box.getWidth(), box.getHeight());
        }
        return "Page " + pageNumber + " (Offset " + startOffset + "-" + endOffset + ")";
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
                pageNumber,
                detectionMethod,
                detectionReason,
                redactionStatus,
                boundingBoxes,
                maskedPreview,
                replacementToken,
                selected);
    }

    /**
     * Returns a copy of this match enriched with PDF page, method, reason, status, and coordinate boxes.
     */
    public RedactionMatch withPageAndCoordinates(
            int newPageNumber,
            DetectionMethod newMethod,
            String newReason,
            RedactionStatus newStatus,
            List<PdfBoundingBox> newBoxes,
            int newStartOffset,
            int newEndOffset) {
        return new RedactionMatch(
                matchId,
                candidateType,
                ruleId,
                confidence,
                newStartOffset,
                newEndOffset,
                rowIndex,
                columnIndex,
                newPageNumber,
                newMethod,
                newReason,
                newStatus,
                newBoxes,
                maskedPreview,
                replacementToken,
                selectedForRedaction);
    }

    /**
     * Utility method to create a privacy-preserving masked preview of a sensitive string.
     */
    public static String maskValue(String rawValue) {
        if (rawValue == null || rawValue.isEmpty()) {
            return "***";
        }
        String normalized = rawValue.replace('\r', ' ').replace('\n', ' ').trim();
        if (normalized.isEmpty()) {
            return "***";
        }
        int len = normalized.length();
        if (len <= 2) {
            return "*".repeat(len);
        }
        if (len <= 6) {
            return normalized.charAt(0) + "*".repeat(len - 2) + normalized.charAt(len - 1);
        }
        int atIndex = normalized.indexOf('@');
        if (atIndex > 1 && atIndex < len - 1) {
            String local = normalized.substring(0, atIndex);
            String domain = normalized.substring(atIndex);
            String maskedLocal = local.charAt(0) + "***" + (local.length() > 2 ? local.charAt(local.length() - 1) : "");
            return maskedLocal + domain;
        }
        return normalized.substring(0, 2) + "*".repeat(Math.min(6, len - 4)) + normalized.substring(len - 2);
    }

    @Override
    public int compareTo(RedactionMatch other) {
        int pageCmp = Integer.compare(this.pageNumber, other.pageNumber);
        if (pageCmp != 0) {
            return pageCmp;
        }
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
                + ", page=" + pageNumber
                + ", method=" + detectionMethod
                + ", status=" + redactionStatus
                + ", row=" + rowIndex
                + ", col=" + columnIndex
                + ", range=[" + startOffset + "," + endOffset + ")"
                + ", boxes=" + boundingBoxes.size()
                + ", preview='" + maskedPreview + '\''
                + ", selected=" + selectedForRedaction
                + '}';
    }
}
