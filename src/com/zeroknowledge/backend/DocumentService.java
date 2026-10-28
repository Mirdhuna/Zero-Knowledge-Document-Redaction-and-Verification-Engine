package com.zeroknowledge.backend;

import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.document.DocumentHandler;
import com.zeroknowledge.document.PdfDocumentHandler;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.OperationRecord.OperationType;
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
        this.redactionService = new RedactionService(fileStorageService, hashService, accessControlService, auditService);
    }

    /**
     * Inspects a file on disk and returns its {@link DocumentMetadata} (format, size, SHA-256 hash, timestamp).
     * For PDF files, also validates the {@code %PDF-} header.
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
     * Scans a selected document and returns candidate {@link RedactionMatch} items for user review.
     * Candidates are returned with {@code selectedForRedaction = false} so nothing is redacted without user approval.
     *
     * @param sourcePath path to the {@code .txt} or {@code .csv} file
     * @return unmodifiable list of detected candidates
     * @throws DocumentProcessingException if the file is unreadable, malformed, or is a PDF/unsupported format
     */
    public List<RedactionMatch> scanDocument(Path sourcePath) throws DocumentProcessingException {
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
            List<RedactionMatch> matches = handler.scan(sourcePath, sensitiveDataDetector);
            auditService.record(
                    OperationType.DOCUMENT_SCAN,
                    fileName,
                    true,
                    "Scan completed for " + format.name() + "; candidatesFound=" + matches.size());
            return matches;
        } catch (DocumentProcessingException e) {
            OperationType opType = (format == DocumentFormat.PDF)
                    ? OperationType.UNSUPPORTED_PDF_OPERATION
                    : OperationType.DOCUMENT_SCAN;
            auditService.record(opType, fileName, false, e.getMessage());
            throw e;
        }
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
