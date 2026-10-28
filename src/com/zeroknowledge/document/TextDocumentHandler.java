package com.zeroknowledge.document;

import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.storage.FileStorageService;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Document handler for UTF-8 plain-text ({@code .txt}) files.
 */
public final class TextDocumentHandler implements DocumentHandler {

    private final FileStorageService fileStorageService;
    private final HashService hashService;

    public TextDocumentHandler(FileStorageService fileStorageService, HashService hashService) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
    }

    @Override
    public DocumentFormat getSupportedFormat() {
        return DocumentFormat.TXT;
    }

    @Override
    public String readValidatedContent(Path sourcePath) throws DocumentProcessingException {
        Path normalized = fileStorageService.validateReadableSourceFile(sourcePath);
        if (DocumentFormat.fromPath(normalized) != DocumentFormat.TXT) {
            throw new DocumentProcessingException(
                    "TextDocumentHandler only supports .txt files: " + normalized.getFileName());
        }
        return fileStorageService.readUtf8Text(normalized);
    }

    @Override
    public List<RedactionMatch> scan(Path sourcePath, SensitiveDataDetector detector)
            throws DocumentProcessingException {
        Objects.requireNonNull(detector, "detector must not be null");
        String content = readValidatedContent(sourcePath);
        if (content.isEmpty()) {
            return List.of();
        }
        return detector.detectInText(content);
    }

    @Override
    public RedactionResult applyRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        String originalText = readValidatedContent(sourcePath);
        Path targetOutput = (outputPath != null)
                ? outputPath
                : fileStorageService.resolveDefaultRedactedOutputPath(sourcePath);

        List<RedactionMatch> candidates = (approvedMatches == null) ? List.of() : approvedMatches;
        List<String> originalSensitiveSubstrings = new ArrayList<>();
        for (RedactionMatch match : candidates) {
            if (match != null && match.isSelectedForRedaction()) {
                if (match.getStartOffset() < 0 || match.getEndOffset() > originalText.length()
                        || match.getStartOffset() >= match.getEndOffset()) {
                    throw new RedactionException(
                            "Match offset [" + match.getStartOffset() + ", " + match.getEndOffset()
                                    + ") is out of bounds for document length " + originalText.length());
                }
                originalSensitiveSubstrings.add(originalText.substring(match.getStartOffset(), match.getEndOffset()));
            }
        }

        ResolvedRedaction resolved = DocumentHandler.applyMatchesToText(originalText, candidates);
        String redactedText = resolved.getRedactedText();

        Path savedPath = fileStorageService.writeRedactedUtf8Safely(sourcePath, targetOutput, redactedText, true);

        // Post-save verification: reload saved output and verify exact match
        String reloadedText = fileStorageService.readUtf8Text(savedPath);
        if (!reloadedText.equals(redactedText)) {
            throw new RedactionException("Post-save verification failed: saved text does not match expected redacted content");
        }

        String sourceHash = hashService.calculateSha256(sourcePath);
        String outputHash = hashService.calculateSha256(savedPath);

        return new RedactionResult(
                true,
                DocumentFormat.TXT,
                sourcePath.toAbsolutePath().normalize(),
                savedPath,
                sourceHash,
                outputHash,
                candidates.size(),
                resolved.getAppliedMatches().size(),
                resolved.getAppliedMatches(),
                Instant.now(),
                "Successfully applied " + resolved.getAppliedMatches().size()
                        + " user-approved redaction(s) to TXT document (" + originalSensitiveSubstrings.size()
                        + " selected candidate(s) resolved).");
    }
}
