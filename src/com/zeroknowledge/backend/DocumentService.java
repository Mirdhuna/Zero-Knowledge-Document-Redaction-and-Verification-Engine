package com.zeroknowledge.backend;

import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.document.DocumentHandler;
import com.zeroknowledge.document.PdfDocumentHandler;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.DocumentScanReport;
import com.zeroknowledge.model.DocumentScanReport.ScanOutcome;
import com.zeroknowledge.model.OperationRecord.OperationType;
import com.zeroknowledge.model.PageExtractionReport;
import com.zeroknowledge.model.PageExtractionReport.PageStatus;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.AuditService;
import com.zeroknowledge.storage.FileStorageService;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Primary frontend-facing facade for document inspection, sensitive-data scanning,
 * redaction execution, and format capability queries.
 */
public final class DocumentService {

    private final FileStorageService fileStorageService;
    private final SensitiveDataDetector sensitiveDataDetector;
    private final RedactionService redactionService;
    private final AccessControlService accessControlService;
    private final AuditService auditService;
    private volatile DocumentScanReport lastScanReport;

    public DocumentService(
            FileStorageService fileStorageService,
            SensitiveDataDetector sensitiveDataDetector,
            RedactionService redactionService,
            AccessControlService accessControlService,
            AuditService auditService) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
        this.sensitiveDataDetector = Objects.requireNonNull(sensitiveDataDetector, "sensitiveDataDetector must not be null");
        this.redactionService = Objects.requireNonNull(redactionService, "redactionService must not be null");
        this.accessControlService = Objects.requireNonNull(accessControlService, "accessControlService must not be null");
        this.auditService = Objects.requireNonNull(auditService, "auditService must not be null");
    }

    /**
     * Convenience constructor wiring default services.
     */
    public DocumentService() {
        ApplicationConfig config = ApplicationConfig.createDefault();
        HashService hashService = new HashService();
        this.auditService = new AuditService(config);
        this.accessControlService = new AccessControlService(AccessControlService.Role.SECURITY_ADMINISTRATOR, auditService);
        this.fileStorageService = new FileStorageService(config, hashService);
        this.sensitiveDataDetector = new SensitiveDataDetector();
        this.redactionService = new RedactionService(fileStorageService, hashService, accessControlService, auditService, config);
    }

    /**
     * Inspects a file on disk and returns its {@link DocumentMetadata} (format, size, SHA-256 hash, timestamp).
     * For PDF files, also validates the {@code %PDF-} header and structural integrity.
     */
    public DocumentMetadata inspectDocument(Path filePath) throws DocumentProcessingException {
        accessControlService.requirePermission(AccessControlService.Permission.CALCULATE_HASH);
        DocumentMetadata metadata = fileStorageService.inspectDocument(filePath);
        if (metadata.getFormat() == DocumentFormat.PDF) {
            DocumentHandler pdfHandler = redactionService.getHandler(DocumentFormat.PDF);
            if (pdfHandler instanceof PdfDocumentHandler pdf) {
                pdf.validatePdfHeader(filePath);
            }
        }
        return metadata;
    }

    /**
     * Scans a document and returns a detailed {@link DocumentScanReport} including per-page native/OCR
     * extraction status, OCR availability diagnostics, and detected {@link RedactionMatch} candidates.
     */
    public DocumentScanReport scanDocumentWithReport(Path sourcePath) throws DocumentProcessingException {
        accessControlService.requirePermission(AccessControlService.Permission.SCAN_DOCUMENT);
        if (sourcePath == null) {
            throw new DocumentProcessingException("Document path must not be null");
        }
        String fileName = sourcePath.getFileName() != null ? sourcePath.getFileName().toString() : "unknown";
        DocumentFormat format = DocumentFormat.fromPath(sourcePath);

        if (format == DocumentFormat.UNSUPPORTED) {
            auditService.record(OperationType.DOCUMENT_SCAN, fileName, false, "Unsupported document format");
            throw new DocumentProcessingException("Unsupported document format: " + fileName);
        }

        DocumentHandler handler = redactionService.getHandler(format);
        try {
            if (format == DocumentFormat.PDF && handler instanceof PdfDocumentHandler pdf) {
                DocumentScanReport report = pdf.scanWithReport(sourcePath, sensitiveDataDetector);
                this.lastScanReport = report;
                if (report.getOutcome() == ScanOutcome.EXTRACTION_FAILED) {
                    auditService.record(OperationType.DOCUMENT_SCAN, fileName, false, report.getSummaryMessage());
                    throw new DocumentProcessingException(report.getSummaryMessage());
                }
                auditService.record(
                        OperationType.DOCUMENT_SCAN,
                        fileName,
                        true,
                        "Scan completed for PDF (" + report.getOutcome().name()
                                + ", pages=" + report.getTotalPages()
                                + ", failedPages=" + report.getPagesFailed()
                                + ", candidatesFound=" + report.getMatches().size() + ")");
                return report;
            }

            List<RedactionMatch> matches = handler.scan(sourcePath, sensitiveDataDetector);
            String rawContent = handler.readValidatedContent(sourcePath);
            PageExtractionReport singlePage = new PageExtractionReport(
                    1,
                    rawContent.isEmpty() ? PageStatus.EMPTY_PAGE : PageStatus.NATIVE_TEXT_EXTRACTED,
                    !rawContent.isEmpty(),
                    false,
                    false,
                    false,
                    1.0,
                    rawContent.length(),
                    0,
                    612.0,
                    792.0,
                    format.name() + " content extracted (" + rawContent.length() + " chars).");
            ScanOutcome outcome = matches.isEmpty() ? ScanOutcome.SUCCESS_NO_MATCHES : ScanOutcome.SUCCESS_WITH_MATCHES;
            String summary = matches.isEmpty()
                    ? "Extracted " + format.name() + " document successfully. No sensitive content found."
                    : "Extracted " + format.name() + " document and detected " + matches.size() + " sensitive item(s).";

            DocumentScanReport report = new DocumentScanReport(
                    sourcePath.toAbsolutePath().normalize(),
                    format,
                    outcome,
                    1,
                    1,
                    0,
                    rawContent.isEmpty() ? 0 : 1,
                    0,
                    rawContent.isEmpty() ? 1 : 0,
                    true,
                    "Native text format (" + format.name() + ")",
                    List.of(singlePage),
                    matches,
                    summary);
            this.lastScanReport = report;
            auditService.record(
                    OperationType.DOCUMENT_SCAN,
                    fileName,
                    true,
                    "Scan completed for " + format.name() + "; candidatesFound=" + matches.size());
            return report;
        } catch (DocumentProcessingException e) {
            auditService.record(OperationType.DOCUMENT_SCAN, fileName, false, e.getMessage());
            throw e;
        }
    }

    /**
     * Scans a selected document and returns candidate {@link RedactionMatch} items for user review.
     * Candidates are returned with {@code selectedForRedaction = false} so nothing is redacted without user approval.
     */
    public List<RedactionMatch> scanDocument(Path sourcePath) throws DocumentProcessingException {
        return scanDocumentWithReport(sourcePath).getMatches();
    }

    /**
     * Returns the most recent {@link DocumentScanReport} produced by {@link #scanDocument(Path)}
     * or {@link #scanDocumentWithReport(Path)}.
     */
    public DocumentScanReport getLastScanReport() {
        return lastScanReport;
    }

    /**
     * Applies user-approved {@link RedactionMatch} items to {@code sourcePath} and saves the redacted artifact
     * to {@code outputPath} (or a safe default `.redacted` path if {@code outputPath} is null).
     */
    public RedactionResult applyApprovedRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        if (outputPath == null) {
            return redactionService.redactToDefaultOutput(sourcePath, approvedMatches);
        }
        return redactionService.redact(sourcePath, outputPath, approvedMatches);
    }

    /**
     * Applies user-approved {@link RedactionMatch} items and writes to a default non-overwriting output path.
     */
    public RedactionResult applyApprovedRedactions(
            Path sourcePath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        return redactionService.redactToDefaultOutput(sourcePath, approvedMatches);
    }

    /**
     * Returns the {@link DocumentFormat} and capability profile for a file path.
     */
    public DocumentFormat detectFormat(Path filePath) {
        return DocumentFormat.fromPath(filePath);
    }

    /**
     * Returns all supported {@link DocumentFormat} enum values (excluding {@code UNSUPPORTED}).
     */
    public List<DocumentFormat> getSupportedFormats() {
        return List.of(DocumentFormat.TXT, DocumentFormat.CSV, DocumentFormat.PDF);
    }

    /**
     * Returns whether sensitive-data text scanning and redaction are supported for the given file path.
     */
    public boolean isRedactionSupported(Path filePath) {
        DocumentFormat format = DocumentFormat.fromPath(filePath);
        return format.isRedactionSupported();
    }

    /**
     * Returns whether whole-file SHA-256 hashing and detached RSA signing/verification are supported for the path.
     */
    public boolean isVerificationSupported(Path filePath) {
        DocumentFormat format = DocumentFormat.fromPath(filePath);
        return format.isSigningAndVerificationSupported();
    }

    public SensitiveDataDetector getSensitiveDataDetector() {
        return sensitiveDataDetector;
    }

    public RedactionService getRedactionService() {
        return redactionService;
    }

    public FileStorageService getFileStorageService() {
        return fileStorageService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public AccessControlService getAccessControlService() {
        return accessControlService;
    }
}
