package com.zeroknowledge.document;

import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.storage.FileStorageService;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Capability-boundary handler for Portable Document Format ({@code .pdf}) files.
 *
 * <h3>Security Rationale & Capability Boundary</h3>
 * <p>Java 21's standard library does not include a PDF parser, Flate/LZW object-stream decoder,
 * font CMap glyph mapper, or cross-reference table reconstructor. Attempting to redact PDFs using
 * raw byte regular expressions or drawing black overlays fails to remove underlying glyph data,
 * incremental update revisions, XMP metadata, or embedded streams—creating a severe false sense of security.
 *
 * <p>Therefore, this handler:
 * <ul>
 *   <li><strong>Supports:</strong> PDF magic-header validation ({@code %PDF-}), file metadata inspection,
 *       whole-file SHA-256 hashing (via {@code HashService}), and detached RSA digital signature creation
 *       and verification (via {@code SignatureService} and {@code VerificationService}).</li>
 *   <li><strong>Explicitly Rejects:</strong> Text extraction, sensitive-data scanning, and in-document PDF redaction,
 *       returning clear unsupported-operation errors or results so the application never falsely claims PDF redaction succeeded.</li>
 * </ul>
 */
public final class PdfDocumentHandler implements DocumentHandler {

    private static final byte[] PDF_MAGIC_HEADER = "%PDF-".getBytes(StandardCharsets.US_ASCII);
    public static final String UNSUPPORTED_PDF_REDACTION_MESSAGE =
            "UNSUPPORTED OPERATION: Safe PDF text extraction and content-stream redaction cannot be performed "
                    + "under the standard-JDK-only constraint without risking residual confidential data in compressed "
                    + "streams, font tables, or incremental updates. Whole-file SHA-256 hashing and detached RSA "
                    + "signature verification remain supported for PDF artifacts.";

    private final FileStorageService fileStorageService;

    public PdfDocumentHandler(FileStorageService fileStorageService) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
    }

    @Override
    public DocumentFormat getSupportedFormat() {
        return DocumentFormat.PDF;
    }

    /**
     * Validates that the file exists, has a {@code .pdf} extension, and begins with the {@code %PDF-} header.
     */
    public void validatePdfHeader(Path sourcePath) throws DocumentProcessingException {
        Path normalized = fileStorageService.validateReadableSourceFile(sourcePath);
        if (DocumentFormat.fromPath(normalized) != DocumentFormat.PDF) {
            throw new DocumentProcessingException("File does not have a .pdf extension: " + normalized.getFileName());
        }
        byte[] header = new byte[PDF_MAGIC_HEADER.length];
        try (InputStream in = Files.newInputStream(normalized)) {
            int read = in.read(header);
            if (read < PDF_MAGIC_HEADER.length) {
                throw new DocumentProcessingException(
                        "Invalid PDF file (missing %PDF- magic header): " + normalized.getFileName());
            }
            for (int i = 0; i < PDF_MAGIC_HEADER.length; i++) {
                if (header[i] != PDF_MAGIC_HEADER[i]) {
                    throw new DocumentProcessingException(
                            "File does not begin with a valid %PDF- header: " + normalized.getFileName());
                }
            }
        } catch (IOException e) {
            throw new DocumentProcessingException("Failed to read PDF file header: " + normalized.getFileName(), e);
        }
    }

    @Override
    public String readValidatedContent(Path sourcePath) throws DocumentProcessingException {
        validatePdfHeader(sourcePath);
        throw new DocumentProcessingException(UNSUPPORTED_PDF_REDACTION_MESSAGE);
    }

    @Override
    public List<RedactionMatch> scan(Path sourcePath, SensitiveDataDetector detector)
            throws DocumentProcessingException {
        validatePdfHeader(sourcePath);
        throw new DocumentProcessingException(UNSUPPORTED_PDF_REDACTION_MESSAGE);
    }

    @Override
    public RedactionResult applyRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        validatePdfHeader(sourcePath);
        return new RedactionResult(
                false,
                DocumentFormat.PDF,
                sourcePath.toAbsolutePath().normalize(),
                null,
                null,
                null,
                approvedMatches == null ? 0 : approvedMatches.size(),
                0,
                List.of(),
                Instant.now(),
                UNSUPPORTED_PDF_REDACTION_MESSAGE);
    }
}
