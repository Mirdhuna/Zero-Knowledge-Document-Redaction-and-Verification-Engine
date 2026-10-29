package com.zeroknowledge.model;

import com.zeroknowledge.document.DocumentFormat;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Comprehensive scan and extraction report for a document.
 * Explicitly distinguishes successful extraction with no matches from OCR unavailability,
 * low-confidence OCR, partial page extraction failures, and total extraction failure.
 */
public final class DocumentScanReport {

    public enum ScanOutcome {
        /** Extraction succeeded across all pages and one or more sensitive candidates were detected. */
        SUCCESS_WITH_MATCHES,
        /** Extraction succeeded across all pages and zero sensitive candidates exist in the document. */
        SUCCESS_NO_MATCHES,
        /** Document contains scanned image page(s), but local Tesseract OCR executable or language data is unavailable. */
        OCR_UNAVAILABLE,
        /** OCR ran on scanned page(s), but word recognition confidence was low; manual review is required. */
        LOW_CONFIDENCE_OCR,
        /** One or more pages failed extraction or OCR while other pages were processed. */
        PARTIAL_EXTRACTION_FAILURE,
        /** Document extraction failed completely. */
        EXTRACTION_FAILED
    }

    private final Path documentPath;
    private final DocumentFormat format;
    private final ScanOutcome outcome;
    private final int totalPages;
    private final int pagesProcessed;
    private final int pagesFailed;
    private final int nativeTextPages;
    private final int ocrPages;
    private final int emptyPages;
    private final boolean ocrAvailable;
    private final String ocrDiagnosticMessage;
    private final List<PageExtractionReport> pageReports;
    private final List<RedactionMatch> matches;
    private final String summaryMessage;

    public DocumentScanReport(
            Path documentPath,
            DocumentFormat format,
            ScanOutcome outcome,
            int totalPages,
            int pagesProcessed,
            int pagesFailed,
            int nativeTextPages,
            int ocrPages,
            int emptyPages,
            boolean ocrAvailable,
            String ocrDiagnosticMessage,
            List<PageExtractionReport> pageReports,
            List<RedactionMatch> matches,
            String summaryMessage) {
        this.documentPath = documentPath;
        this.format = Objects.requireNonNull(format, "format must not be null");
        this.outcome = Objects.requireNonNull(outcome, "outcome must not be null");
        this.totalPages = Math.max(0, totalPages);
        this.pagesProcessed = Math.max(0, pagesProcessed);
        this.pagesFailed = Math.max(0, pagesFailed);
        this.nativeTextPages = Math.max(0, nativeTextPages);
        this.ocrPages = Math.max(0, ocrPages);
        this.emptyPages = Math.max(0, emptyPages);
        this.ocrAvailable = ocrAvailable;
        this.ocrDiagnosticMessage = ocrDiagnosticMessage == null ? "" : ocrDiagnosticMessage;
        this.pageReports = pageReports == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(pageReports));
        this.matches = matches == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(matches));
        this.summaryMessage = Objects.requireNonNull(summaryMessage, "summaryMessage must not be null");
    }

    public Path getDocumentPath() {
        return documentPath;
    }

    public DocumentFormat getFormat() {
        return format;
    }

    public ScanOutcome getOutcome() {
        return outcome;
    }

    public int getTotalPages() {
        return totalPages;
    }

    public int getPagesProcessed() {
        return pagesProcessed;
    }

    public int getPagesFailed() {
        return pagesFailed;
    }

    public int getNativeTextPages() {
        return nativeTextPages;
    }

    public int getOcrPages() {
        return ocrPages;
    }

    public int getEmptyPages() {
        return emptyPages;
    }

    public boolean isOcrAvailable() {
        return ocrAvailable;
    }

    public String getOcrDiagnosticMessage() {
        return ocrDiagnosticMessage;
    }

    public List<PageExtractionReport> getPageReports() {
        return pageReports;
    }

    public List<RedactionMatch> getMatches() {
        return matches;
    }

    public String getSummaryMessage() {
        return summaryMessage;
    }

    public boolean hasWarningsOrFailures() {
        return outcome == ScanOutcome.OCR_UNAVAILABLE
                || outcome == ScanOutcome.LOW_CONFIDENCE_OCR
                || outcome == ScanOutcome.PARTIAL_EXTRACTION_FAILURE
                || outcome == ScanOutcome.EXTRACTION_FAILED
                || pagesFailed > 0;
    }

    @Override
    public String toString() {
        return "DocumentScanReport{"
                + "outcome=" + outcome
                + ", totalPages=" + totalPages
                + ", pagesProcessed=" + pagesProcessed
                + ", pagesFailed=" + pagesFailed
                + ", matches=" + matches.size()
                + ", summary='" + summaryMessage + '\''
                + '}';
    }
}
