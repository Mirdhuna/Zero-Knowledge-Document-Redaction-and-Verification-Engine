package com.zeroknowledge.model;

import java.util.Objects;

/**
 * Per-page text extraction and OCR status report.
 * Distinguishes native selectable text, OCR on scanned images, hybrid pages,
 * empty pages, low-confidence OCR, unavailable OCR, and extraction failures.
 */
public final class PageExtractionReport {

    public enum PageStatus {
        NATIVE_TEXT_EXTRACTED("Native Text (OK)"),
        OCR_EXTRACTED("Scanned Image (OCR OK)"),
        HYBRID_EXTRACTED("Hybrid (Native + OCR OK)"),
        EMPTY_PAGE("Empty Page"),
        LOW_CONFIDENCE_OCR("Low-Confidence OCR (Review)"),
        OCR_UNAVAILABLE("Scanned Page — OCR Unavailable"),
        EXTRACTION_FAILED("Extraction Failed");

        private final String displayName;

        PageStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    private final int pageNumber;
    private final PageStatus status;
    private final boolean nativeTextPresent;
    private final boolean scannedImagePresent;
    private final boolean ocrAttempted;
    private final boolean ocrSucceeded;
    private final double ocrConfidence;
    private final int extractedCharCount;
    private final int rotationDegrees;
    private final double widthPts;
    private final double heightPts;
    private final String diagnosticMessage;

    public PageExtractionReport(
            int pageNumber,
            PageStatus status,
            boolean nativeTextPresent,
            boolean scannedImagePresent,
            boolean ocrAttempted,
            boolean ocrSucceeded,
            double ocrConfidence,
            int extractedCharCount,
            int rotationDegrees,
            double widthPts,
            double heightPts,
            String diagnosticMessage) {
        if (pageNumber < 1) {
            throw new IllegalArgumentException("pageNumber must be >= 1");
        }
        this.pageNumber = pageNumber;
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.nativeTextPresent = nativeTextPresent;
        this.scannedImagePresent = scannedImagePresent;
        this.ocrAttempted = ocrAttempted;
        this.ocrSucceeded = ocrSucceeded;
        this.ocrConfidence = ocrConfidence;
        this.extractedCharCount = Math.max(0, extractedCharCount);
        this.rotationDegrees = ((rotationDegrees % 360) + 360) % 360;
        this.widthPts = widthPts;
        this.heightPts = heightPts;
        this.diagnosticMessage = diagnosticMessage == null ? "" : diagnosticMessage;
    }

    public int getPageNumber() {
        return pageNumber;
    }

    public PageStatus getStatus() {
        return status;
    }

    public boolean isNativeTextPresent() {
        return nativeTextPresent;
    }

    public boolean isScannedImagePresent() {
        return scannedImagePresent;
    }

    public boolean isOcrAttempted() {
        return ocrAttempted;
    }

    public boolean isOcrSucceeded() {
        return ocrSucceeded;
    }

    public double getOcrConfidence() {
        return ocrConfidence;
    }

    public int getExtractedCharCount() {
        return extractedCharCount;
    }

    public int getRotationDegrees() {
        return rotationDegrees;
    }

    public double getWidthPts() {
        return widthPts;
    }

    public double getHeightPts() {
        return heightPts;
    }

    public String getDiagnosticMessage() {
        return diagnosticMessage;
    }

    public boolean isFailedOrUnavailable() {
        return status == PageStatus.EXTRACTION_FAILED || status == PageStatus.OCR_UNAVAILABLE;
    }

    @Override
    public String toString() {
        return "Page " + pageNumber + ": " + status.getDisplayName()
                + (diagnosticMessage.isEmpty() ? "" : " (" + diagnosticMessage + ")");
    }
}
