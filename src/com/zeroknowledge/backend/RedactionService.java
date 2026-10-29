package com.zeroknowledge.backend;

import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.document.CsvDocumentHandler;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.document.DocumentHandler;
import com.zeroknowledge.document.OcrEngine;
import com.zeroknowledge.document.PdfDocumentHandler;
import com.zeroknowledge.document.TesseractOcrEngine;
import com.zeroknowledge.document.TextDocumentHandler;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.OperationRecord.OperationType;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.AuditService;
import com.zeroknowledge.storage.FileStorageService;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Coordinates format-specific redaction execution, source-file protection,
 * post-redaction verification, and privacy-safe audit logging.
 */
public final class RedactionService {

    private final FileStorageService fileStorageService;
    private final AccessControlService accessControlService;
    private final AuditService auditService;
    private final Map<DocumentFormat, DocumentHandler> handlers;

    public RedactionService(
            FileStorageService fileStorageService,
            HashService hashService,
            AccessControlService accessControlService,
            AuditService auditService) {
        this(fileStorageService, hashService, accessControlService, auditService,
                ApplicationConfig.createDefault(),
                null);
    }

    public RedactionService(
            FileStorageService fileStorageService,
            HashService hashService,
            AccessControlService accessControlService,
            AuditService auditService,
            ApplicationConfig config) {
        this(fileStorageService, hashService, accessControlService, auditService, config, null);
    }

    public RedactionService(
            FileStorageService fileStorageService,
            HashService hashService,
            AccessControlService accessControlService,
            AuditService auditService,
            ApplicationConfig config,
            OcrEngine customOcrEngine) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
        Objects.requireNonNull(hashService, "hashService must not be null");
        this.accessControlService = Objects.requireNonNull(accessControlService, "accessControlService must not be null");
        this.auditService = Objects.requireNonNull(auditService, "auditService must not be null");

        ApplicationConfig effectiveConfig = (config != null) ? config : ApplicationConfig.createDefault();
        OcrEngine ocrEngine = (customOcrEngine != null) ? customOcrEngine : new TesseractOcrEngine(effectiveConfig);

        this.handlers = new EnumMap<>(DocumentFormat.class);
        this.handlers.put(DocumentFormat.TXT, new TextDocumentHandler(fileStorageService, hashService));
        this.handlers.put(DocumentFormat.CSV, new CsvDocumentHandler(fileStorageService, hashService));
        this.handlers.put(DocumentFormat.PDF, new PdfDocumentHandler(fileStorageService, hashService, effectiveConfig, ocrEngine));
    }

    /**
     * Applies user-approved redactions to {@code sourcePath} and writes the output to a separate default file
     * (e.g. {@code document.redacted.pdf}).
     */
    public RedactionResult redactToDefaultOutput(Path sourcePath, List<RedactionMatch> approvedMatches)
            throws DocumentProcessingException, RedactionException {
        Path defaultOutput = fileStorageService.resolveDefaultRedactedOutputPath(sourcePath);
        return redact(sourcePath, defaultOutput, approvedMatches);
    }

    /**
     * Applies user-approved redactions to {@code sourcePath} and writes the output to {@code outputPath}.
     * Never overwrites {@code sourcePath}.
     */
    public RedactionResult redact(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        accessControlService.requirePermission(AccessControlService.Permission.REDACT_DOCUMENT);
        if (sourcePath == null) {
            throw new DocumentProcessingException("Source path must not be null");
        }
        String fileName = sourcePath.getFileName() != null ? sourcePath.getFileName().toString() : "unknown";
        DocumentFormat format = DocumentFormat.fromPath(sourcePath);

        if (format == DocumentFormat.UNSUPPORTED) {
            auditService.record(
                    OperationType.DOCUMENT_REDACT,
                    fileName,
                    false,
                    "Unsupported document format for redaction");
            throw new DocumentProcessingException("Unsupported document format: " + fileName);
        }

        DocumentHandler handler = handlers.get(format);
        try {
            RedactionResult result = handler.applyRedactions(sourcePath, outputPath, approvedMatches);
            if (!result.isSuccess()) {
                auditService.record(
                        OperationType.DOCUMENT_REDACT,
                        fileName,
                        false,
                        result.getSummaryMessage());
            } else {
                auditService.record(
                        OperationType.DOCUMENT_REDACT,
                        fileName,
                        true,
                        "Applied " + result.getApprovedMatchesApplied()
                                + " match(es) (skipped=" + result.getSkippedMatchesCount()
                                + ", verification=" + result.getVerificationStatus().name()
                                + "); outputSha256=" + result.getOutputSha256());
            }
            return result;
        } catch (DocumentProcessingException | RedactionException | RuntimeException e) {
            auditService.record(
                    OperationType.DOCUMENT_REDACT,
                    fileName,
                    false,
                    "Redaction failed (" + e.getClass().getSimpleName() + ")");
            throw e;
        }
    }

    /**
     * Exposes the registered {@link DocumentHandler} for a given format.
     */
    public DocumentHandler getHandler(DocumentFormat format) {
        return handlers.get(format);
    }

    /**
     * Convenience accessor for the configured {@link PdfDocumentHandler}.
     */
    public PdfDocumentHandler getPdfDocumentHandler() {
        DocumentHandler h = handlers.get(DocumentFormat.PDF);
        return (h instanceof PdfDocumentHandler pdf) ? pdf : null;
    }
}
