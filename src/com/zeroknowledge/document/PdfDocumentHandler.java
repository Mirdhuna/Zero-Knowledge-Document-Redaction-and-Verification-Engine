package com.zeroknowledge.document;

import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.document.OcrEngine.OcrAvailability;
import com.zeroknowledge.document.OcrEngine.OcrExtractionResult;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.DocumentScanReport;
import com.zeroknowledge.model.DocumentScanReport.ScanOutcome;
import com.zeroknowledge.model.PageExtractionReport;
import com.zeroknowledge.model.PageExtractionReport.PageStatus;
import com.zeroknowledge.model.PdfBoundingBox;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionMatch.DetectionMethod;
import com.zeroknowledge.model.RedactionMatch.RedactionStatus;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.model.RedactionResult.VerificationStatus;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.FileStorageService;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import javax.imageio.ImageIO;

/**
 * Page-by-page PDF extraction, coordinate mapping, OCR integration, permanent content/image redaction,
 * and independent post-redaction verification handler ({@code .pdf}).
 *
 * <h3>Capabilities</h3>
 * <ul>
 *   <li><strong>Page-by-Page Native Extraction</strong>: Resolves PDF page trees ({@code /Catalog} &rarr;
 *       {@code /Pages} &rarr; {@code /Page}), inherits {@code /MediaBox}, {@code /CropBox}, {@code /Rotate},
 *       and {@code /Resources}, and interprets PDF graphics/text state operators ({@code cm}, {@code BT..ET},
 *       {@code Tm}, {@code Td}, {@code TD}, {@code T*}, {@code TL}, {@code Tf}, {@code Tc}, {@code Tw},
 *       {@code Tz}, {@code Tj}, {@code TJ}, {@code '}, {@code "}) to compute exact character bounding boxes.</li>
 *   <li><strong>Scanned &amp; Hybrid PDF OCR</strong>: Decodes embedded {@code /Subtype /Image} XObjects
 *       ({@code /DCTDecode} JPEG, {@code /FlateDecode} RGB/Grayscale rasters, PNG streams), preprocesses
 *       images via {@link ImagePreprocessor}, and runs local {@link OcrEngine} ({@link TesseractOcrEngine})
 *       retaining word-level coordinates and confidence.</li>
 *   <li><strong>Explicit Extraction Statuses</strong>: Distinguishes selectable native text, OCR text,
 *       hybrid pages, empty pages, low-confidence OCR, unavailable OCR, and extraction failure.</li>
 *   <li><strong>Permanent Native &amp; Image Redaction</strong>: Excises underlying sensitive characters
 *       from content stream text operators (preserving layout of unselected text via {@code TJ} kerning shifts),
 *       draws opaque redaction bars over target coordinates, and permanently overwrites sensitive pixel
 *       regions in scanned page images while discarding original unredacted image streams.</li>
 *   <li><strong>Independent Post-Redaction Verification</strong>: Reopens the saved output PDF from disk,
 *       re-extracts text streams and image rasters, and verifies that no redacted text or unredacted image
 *       pixels remain recoverable.</li>
 * </ul>
 */
public final class PdfDocumentHandler implements DocumentHandler {

    private static final byte[] PDF_MAGIC_HEADER = "%PDF-".getBytes(StandardCharsets.US_ASCII);

    private final FileStorageService fileStorageService;
    private final HashService hashService;
    private final ApplicationConfig config;
    private volatile OcrEngine ocrEngine;
    private volatile DocumentScanReport lastScanReport;

    public PdfDocumentHandler(FileStorageService fileStorageService) {
        this(fileStorageService, new HashService(), ApplicationConfig.createDefault(), null);
    }

    public PdfDocumentHandler(FileStorageService fileStorageService, HashService hashService) {
        this(fileStorageService, hashService, ApplicationConfig.createDefault(), null);
    }

    public PdfDocumentHandler(
            FileStorageService fileStorageService,
            HashService hashService,
            ApplicationConfig config,
            OcrEngine ocrEngine) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
        this.config = config != null ? config : ApplicationConfig.createDefault();
        this.ocrEngine = ocrEngine != null ? ocrEngine : new TesseractOcrEngine(this.config);
    }

    public void setOcrEngine(OcrEngine ocrEngine) {
        this.ocrEngine = Objects.requireNonNull(ocrEngine, "ocrEngine must not be null");
    }

    public OcrEngine getOcrEngine() {
        return ocrEngine;
    }

    public DocumentScanReport getLastScanReport() {
        return lastScanReport;
    }

    @Override
    public DocumentFormat getSupportedFormat() {
        return DocumentFormat.PDF;
    }

    /**
     * Validates that the file exists, has a {@code .pdf} extension, begins with {@code %PDF-},
     * and contains a structurally readable PDF trailer/EOF marker.
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
                        "Invalid or truncated PDF file (missing %PDF- magic header): " + normalized.getFileName());
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
        byte[] rawBytes = readPdfBytes(sourcePath);
        PdfParsedDocument doc = parsePdf(rawBytes, sourcePath.getFileName().toString());
        ExtractedDocumentData data = extractDocumentPages(doc, sourcePath, false);
        if (data.pagesFailed == data.totalPages && data.totalPages > 0) {
            throw new DocumentProcessingException(
                    "Failed to extract readable content from any page of PDF: " + sourcePath.getFileName());
        }
        return data.fullConcatenatedText;
    }

    @Override
    public List<RedactionMatch> scan(Path sourcePath, SensitiveDataDetector detector)
            throws DocumentProcessingException {
        DocumentScanReport report = scanWithReport(sourcePath, detector);
        return report.getMatches();
    }

    /**
     * Performs a full page-by-page extraction (native text + OCR for scanned/hybrid pages),
     * maps every detection to exact page coordinates, and returns a detailed {@link DocumentScanReport}.
     */
    public DocumentScanReport scanWithReport(Path sourcePath, SensitiveDataDetector detector)
            throws DocumentProcessingException {
        validatePdfHeader(sourcePath);
        Objects.requireNonNull(detector, "detector must not be null");

        byte[] rawBytes = readPdfBytes(sourcePath);
        PdfParsedDocument doc = parsePdf(rawBytes, sourcePath.getFileName().toString());
        ExtractedDocumentData extracted = extractDocumentPages(doc, sourcePath, true);

        if (extracted.totalPages == 0) {
            throw new DocumentProcessingException(
                    "Malformed PDF: document contains no valid pages (" + sourcePath.getFileName() + ")");
        }
        if (extracted.pagesFailed == extracted.totalPages) {
            throw new DocumentProcessingException(
                    "PDF text/image extraction failed on all " + extracted.totalPages
                            + " page(s): " + extracted.firstErrorMessage);
        }

        List<RedactionMatch> allMatches = new ArrayList<>();
        int globalMatchSeq = 1;

        for (ExtractedPageData pageData : extracted.pages) {
            int pageNum = pageData.pageNumber;

            // 1. Detect in native selectable text on this page
            if (!pageData.nativeText.isBlank()) {
                List<RedactionMatch> nativeCandidates = detector.detectInPageText(
                        pageData.nativeText, pageNum, DetectionMethod.NATIVE_TEXT, false);

                for (RedactionMatch m : nativeCandidates) {
                    List<PdfBoundingBox> boxes = mapNativeTextSpanToBoxes(
                            pageData, m.getStartOffset(), m.getEndOffset());
                    RedactionStatus status = m.getRedactionStatus();
                    String reason = m.getDetectionReason();
                    if (boxes.isEmpty()) {
                        status = RedactionStatus.UNMAPPED_UNSAFE;
                        reason = reason + " [Warning: coordinates could not be mapped]";
                    }
                    int docStart = pageData.globalNativeOffsetStart + m.getStartOffset();
                    int docEnd = pageData.globalNativeOffsetStart + m.getEndOffset();

                    allMatches.add(new RedactionMatch(
                            "PDF_P" + pageNum + "_M" + (globalMatchSeq++),
                            m.getCandidateType(),
                            m.getRuleId(),
                            m.getConfidence(),
                            docStart,
                            docEnd,
                            -1,
                            -1,
                            pageNum,
                            DetectionMethod.NATIVE_TEXT,
                            reason,
                            status,
                            boxes,
                            m.getMaskedPreview(),
                            m.getReplacementToken(),
                            false));
                }
            }

            // 2. Detect in OCR text from scanned/embedded images on this page
            for (PageOcrSegment ocrSeg : pageData.ocrSegments) {
                OcrExtractionResult ocrRes = ocrSeg.ocrResult;
                if (ocrRes != null && ocrRes.isSuccess() && !ocrRes.getExtractedText().isBlank()) {
                    List<RedactionMatch> ocrCandidates = detector.detectInPageText(
                            ocrRes.getExtractedText(), pageNum, DetectionMethod.OCR, true);

                    for (RedactionMatch m : ocrCandidates) {
                        List<PdfBoundingBox> boxes = ocrRes.mapSpanToBoundingBoxes(
                                m.getStartOffset(), m.getEndOffset());
                        double wordConf = ocrRes.getConfidenceForSpan(m.getStartOffset(), m.getEndOffset());
                        double combinedConf = Math.min(m.getConfidence(), Math.max(0.40, wordConf));

                        RedactionStatus status = m.getRedactionStatus();
                        String reason = m.getDetectionReason()
                                + String.format(Locale.ROOT, " [OCR conf=%.0f%%]", wordConf * 100.0);

                        if (boxes.isEmpty()) {
                            status = RedactionStatus.UNMAPPED_UNSAFE;
                            reason = reason + " [Uncertain OCR coordinates — cannot safely auto-redact]";
                        } else if (wordConf < config.getMinOcrConfidence() || combinedConf < 0.72) {
                            status = RedactionStatus.MANUAL_REVIEW_REQUIRED;
                            reason = reason + " [Low OCR confidence — manual review flagged]";
                        }

                        int docStart = ocrSeg.globalTextOffsetStart + m.getStartOffset();
                        int docEnd = ocrSeg.globalTextOffsetStart + m.getEndOffset();

                        allMatches.add(new RedactionMatch(
                                "OCR_P" + pageNum + "_M" + (globalMatchSeq++),
                                m.getCandidateType(),
                                m.getRuleId(),
                                combinedConf,
                                docStart,
                                docEnd,
                                -1,
                                -1,
                                pageNum,
                                pageData.hasNativeText ? DetectionMethod.HYBRID : DetectionMethod.OCR,
                                reason,
                                status,
                                boxes,
                                m.getMaskedPreview(),
                                m.getReplacementToken(),
                                false));
                    }
                }
            }
        }

        // Determine overall ScanOutcome honestly (never claim "No sensitive content found" if OCR/extraction failed!)
        ScanOutcome outcome;
        String summary;

        if (extracted.pagesFailed == extracted.totalPages) {
            outcome = ScanOutcome.EXTRACTION_FAILED;
            summary = "Extraction failed on all " + extracted.totalPages + " page(s). Cannot determine if sensitive content exists.";
        } else if (extracted.pagesFailed > 0) {
            outcome = ScanOutcome.PARTIAL_EXTRACTION_FAILURE;
            summary = "Warning: " + extracted.pagesFailed + " of " + extracted.totalPages
                    + " page(s) failed extraction. Found " + allMatches.size()
                    + " candidate(s) on readable pages; failed pages could not be inspected.";
        } else if (extracted.ocrUnavailablePages > 0) {
            outcome = ScanOutcome.OCR_UNAVAILABLE;
            summary = "OCR Unavailable: " + extracted.ocrUnavailablePages + " scanned page(s) could not be read because "
                    + "local Tesseract OCR is not installed or configured. Do NOT assume the document is free of sensitive data.";
        } else if (extracted.lowConfidenceOcrPages > 0) {
            outcome = ScanOutcome.LOW_CONFIDENCE_OCR;
            summary = "Low-confidence OCR on " + extracted.lowConfidenceOcrPages + " page(s). Detected "
                    + allMatches.size() + " candidate(s); manual review is strongly recommended.";
        } else if (!allMatches.isEmpty()) {
            outcome = ScanOutcome.SUCCESS_WITH_MATCHES;
            summary = "Successfully processed all " + extracted.totalPages + " page(s) ("
                    + extracted.nativePages + " native, " + extracted.ocrPages + " OCR). Detected "
                    + allMatches.size() + " sensitive candidate(s).";
        } else {
            outcome = ScanOutcome.SUCCESS_NO_MATCHES;
            summary = "Successfully processed all " + extracted.totalPages + " page(s) ("
                    + extracted.nativePages + " native, " + extracted.ocrPages + " OCR, "
                    + extracted.emptyPages + " empty). No sensitive content detected.";
        }

        OcrAvailability avail = ocrEngine.checkAvailability();
        String ocrDiag = avail.isAvailable()
                ? avail.getStatusMessage()
                : avail.getStatusMessage() + "\n\n" + avail.getSetupInstructions();

        DocumentScanReport report = new DocumentScanReport(
                sourcePath.toAbsolutePath().normalize(),
                DocumentFormat.PDF,
                outcome,
                extracted.totalPages,
                extracted.pagesProcessed,
                extracted.pagesFailed,
                extracted.nativePages,
                extracted.ocrPages,
                extracted.emptyPages,
                avail.isAvailable(),
                ocrDiag,
                extracted.pageReports,
                Collections.unmodifiableList(allMatches),
                summary);

        this.lastScanReport = report;
        return report;
    }

    @Override
    public RedactionResult applyRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        validatePdfHeader(sourcePath);
        Path targetOutput = (outputPath != null)
                ? fileStorageService.validateSafeOutputDestination(sourcePath, outputPath, true)
                : fileStorageService.validateSafeOutputDestination(
                        sourcePath, fileStorageService.resolveDefaultRedactedOutputPath(sourcePath), true);

        byte[] rawBytes = readPdfBytes(sourcePath);
        String sourceSha256 = hashService.calculateSha256(sourcePath);

        PdfParsedDocument doc = parsePdf(rawBytes, sourcePath.getFileName().toString());
        ExtractedDocumentData extracted = extractDocumentPages(doc, sourcePath, true);

        List<RedactionMatch> allConsidered = (approvedMatches != null) ? approvedMatches : List.of();
        List<RedactionMatch> selected = new ArrayList<>();
        int skippedCount = 0;

        for (RedactionMatch m : allConsidered) {
            if (m == null) continue;
            if (m.isSelectedForRedaction()) {
                if (!m.canBeSafelyRedacted() || m.getRedactionStatus() == RedactionStatus.UNMAPPED_UNSAFE) {
                    throw new RedactionException(
                            "Selected match " + m.getMatchId() + " (" + m.getCandidateType()
                                    + " on page " + m.getPageNumber()
                                    + ") cannot be safely redacted because reliable source coordinates could not be established.");
                }
                selected.add(m);
            } else {
                skippedCount++;
            }
        }

        // Track original sensitive substrings for post-redaction verification
        Map<String, String> matchIdToRawSecret = new LinkedHashMap<>();
        List<RedactionMatch> successfullyApplied = new ArrayList<>();
        int failedCount = 0;

        if (!selected.isEmpty()) {
            // Group selected matches by 1-based pageNumber
            Map<Integer, List<RedactionMatch>> byPage = new LinkedHashMap<>();
            for (RedactionMatch m : selected) {
                int pNum = Math.max(1, m.getPageNumber());
                if (pNum > extracted.totalPages) {
                    throw new RedactionException(
                            "Selected match " + m.getMatchId() + " references out-of-range page "
                                    + pNum + " (document has " + extracted.totalPages + " pages)");
                }
                byPage.computeIfAbsent(pNum, k -> new ArrayList<>()).add(m);
            }

            for (Map.Entry<Integer, List<RedactionMatch>> entry : byPage.entrySet()) {
                int pageNum = entry.getKey();
                List<RedactionMatch> pageMatches = entry.getValue();
                ExtractedPageData pageData = extracted.pages.get(pageNum - 1);

                boolean pageModified = redactPagePermanently(
                        doc, pageData, extracted.fullConcatenatedText, pageMatches, matchIdToRawSecret, successfullyApplied);
                if (!pageModified) {
                    failedCount += pageMatches.size();
                    throw new RedactionException(
                            "Failed to permanently apply selected redactions on page " + pageNum
                                    + ": target content or coordinates could not be resolved in PDF streams.");
                }
            }

            // Also scrub any occurrences in metadata dictionaries (/Title, /Author, /Subject, /Keywords)
            scrubDocumentMetadataDictionaries(doc, matchIdToRawSecret.values(), selected);
        }

        if (successfullyApplied.size() < selected.size()) {
            failedCount = selected.size() - successfullyApplied.size();
            throw new RedactionException(
                    "Redaction aborted: only " + successfullyApplied.size() + " of " + selected.size()
                            + " selected match(es) could be mapped and applied.");
        }

        // Reassemble clean PDF with rebuilt xref table and zero orphaned objects
        byte[] reassembledPdf = assemblePdf(doc);

        try {
            if (targetOutput.getParent() != null) {
                Files.createDirectories(targetOutput.getParent());
            }
            Files.write(targetOutput, reassembledPdf);
        } catch (IOException e) {
            throw new RedactionException("Failed to write redacted PDF to destination: " + targetOutput.getFileName(), e);
        }

        String outputSha256 = hashService.calculateSha256(targetOutput);

        // Stage 5: Independent Post-Redaction Verification by reopening targetOutput from disk
        PostVerificationOutcome postVer = verifySavedPdfIndependently(
                targetOutput, successfullyApplied, matchIdToRawSecret, skippedCount);

        if (postVer.status == VerificationStatus.FAILED) {
            throw new RedactionException(
                    "Post-redaction verification FAILED on output PDF: " + postVer.report);
        }

        String summary = String.format(
                Locale.ROOT,
                "PDF redaction complete (%s). Detected: %d | Selected & Redacted: %d | Skipped: %d | Failed: %d.",
                postVer.status.name(),
                allConsidered.size(),
                successfullyApplied.size(),
                skippedCount,
                failedCount);

        return new RedactionResult(
                true,
                DocumentFormat.PDF,
                sourcePath.toAbsolutePath().normalize(),
                targetOutput.toAbsolutePath().normalize(),
                sourceSha256,
                outputSha256,
                allConsidered.size(),
                selected.size(),
                successfullyApplied.size(),
                skippedCount,
                failedCount,
                successfullyApplied,
                postVer.status,
                postVer.report,
                postVer.warnings,
                Instant.now(),
                summary);
    }

    // =========================================================================
    // Stage 4: Permanent Page-Level Native Text & Image Redaction
    // =========================================================================

    private boolean redactPagePermanently(
            PdfParsedDocument doc,
            ExtractedPageData pageData,
            String fullConcatenatedText,
            List<RedactionMatch> pageMatches,
            Map<String, String> matchIdToRawSecretOut,
            List<RedactionMatch> appliedOut) throws RedactionException {

        List<RedactionMatch> nativeMatches = new ArrayList<>();
        List<RedactionMatch> imageMatches = new ArrayList<>();

        for (RedactionMatch m : pageMatches) {
            String rawSecret = extractRawSecretForMatch(m, pageData, fullConcatenatedText);
            if (!rawSecret.isBlank()) {
                matchIdToRawSecretOut.put(m.getMatchId(), rawSecret);
            }

            if (m.getDetectionMethod() == DetectionMethod.OCR
                    || (m.getDetectionMethod() == DetectionMethod.HYBRID && !pageData.images.isEmpty() && !isNativeMatch(m, pageData))) {
                imageMatches.add(m);
            } else {
                nativeMatches.add(m);
            }
        }

        boolean allSucceeded = true;

        // 1. Permanently redact native text matches
        if (!nativeMatches.isEmpty()) {
            Set<Integer> charIndicesToDelete = new HashSet<>();
            List<PdfBoundingBox> boxesToPaint = new ArrayList<>();

            for (RedactionMatch m : nativeMatches) {
                int localStart = resolveLocalNativeStart(m, pageData);
                int localEnd = resolveLocalNativeEnd(m, pageData);
                String secret = matchIdToRawSecretOut.getOrDefault(m.getMatchId(), "");

                List<PdfBoundingBox> matchBoxes = new ArrayList<>(m.getBoundingBoxes());
                if (localStart >= 0 && localEnd <= pageData.nativeText.length() && localEnd > localStart) {
                    for (int idx = localStart; idx < localEnd; idx++) {
                        charIndicesToDelete.add(idx);
                    }
                    if (matchBoxes.isEmpty()) {
                        matchBoxes.addAll(mapNativeTextSpanToBoxes(pageData, localStart, localEnd));
                    }
                } else if (!secret.isEmpty() && pageData.nativeText.contains(secret)) {
                    int foundIdx = pageData.nativeText.indexOf(secret);
                    while (foundIdx >= 0) {
                        for (int idx = foundIdx; idx < foundIdx + secret.length(); idx++) {
                            charIndicesToDelete.add(idx);
                        }
                        if (matchBoxes.isEmpty()) {
                            matchBoxes.addAll(mapNativeTextSpanToBoxes(pageData, foundIdx, foundIdx + secret.length()));
                        }
                        foundIdx = pageData.nativeText.indexOf(secret, foundIdx + secret.length());
                    }
                }

                if (matchBoxes.isEmpty() && charIndicesToDelete.isEmpty()) {
                    throw new RedactionException(
                            "Cannot safely redact match " + m.getMatchId() + " on page " + pageData.pageNumber
                                    + ": native text offsets and coordinates could not be mapped.");
                }

                boxesToPaint.addAll(matchBoxes);
                appliedOut.add(m.withPageAndCoordinates(
                        pageData.pageNumber,
                        m.getDetectionMethod(),
                        m.getDetectionReason(),
                        RedactionStatus.REDACTABLE,
                        matchBoxes,
                        m.getStartOffset(),
                        m.getEndOffset()));
            }

            // Collect (streamObjNum -> Map<operatorId, Set<charIdxInOp>>) for permanent character deletion
            Map<Integer, Map<Integer, Set<Integer>>> deletionsByStream = new HashMap<>();
            for (int pageCharIdx : charIndicesToDelete) {
                if (pageCharIdx >= 0 && pageCharIdx < pageData.charOrigins.size()) {
                    CharOrigin origin = pageData.charOrigins.get(pageCharIdx);
                    if (origin != null && origin.streamObjNum > 0 && origin.operatorId >= 0) {
                        deletionsByStream
                                .computeIfAbsent(origin.streamObjNum, k -> new HashMap<>())
                                .computeIfAbsent(origin.operatorId, k -> new HashSet<>())
                                .add(origin.charIdxInOperator);
                    }
                }
            }

            // Rewrite each affected content stream on this page
            for (int streamObjNum : pageData.contentStreamObjNums) {
                PdfObject streamObj = doc.getObjectByNumber(streamObjNum);
                if (streamObj == null || streamObj.streamContent == null) {
                    continue;
                }
                Map<Integer, Set<Integer>> opDeletions = deletionsByStream.getOrDefault(streamObjNum, Map.of());
                String rewritten = rewriteStreamRemovingCharacters(
                        streamObj.streamContent,
                        opDeletions,
                        matchIdToRawSecretOut.values());

                // Append opaque black redaction rectangles at the end of the page's last content stream
                if (streamObjNum == pageData.contentStreamObjNums.get(pageData.contentStreamObjNums.size() - 1)
                        && !boxesToPaint.isEmpty()) {
                    rewritten = appendOpaqueRedactionRectangles(rewritten, boxesToPaint, pageData);
                }

                updatePdfStreamObject(streamObj, rewritten.getBytes(StandardCharsets.ISO_8859_1), streamObj.isFlateCompressed);
            }
        }

        // 2. Permanently redact scanned/embedded image matches
        if (!imageMatches.isEmpty()) {
            if (pageData.images.isEmpty()) {
                throw new RedactionException(
                        "Cannot apply OCR image redactions on page " + pageData.pageNumber
                                + ": no page image object found.");
            }

            for (RedactionMatch m : imageMatches) {
                List<PdfBoundingBox> boxes = m.getBoundingBoxes();
                if (boxes.isEmpty()) {
                    throw new RedactionException(
                            "Cannot safely redact OCR match " + m.getMatchId() + " on page " + pageData.pageNumber
                                    + ": bounding box coordinates are missing.");
                }

                boolean paintedOnAnyImage = false;
                for (ExtractedPageImage pageImg : pageData.images) {
                    BufferedImage redactedImg = createRedactedImageCopy(pageImg.image, boxes, pageImg.placementBox);
                    pageImg.image = redactedImg;
                    replacePdfImageObjectPermanently(pageImg.pdfObject, redactedImg);
                    paintedOnAnyImage = true;
                }

                if (!paintedOnAnyImage) {
                    allSucceeded = false;
                } else {
                    appliedOut.add(m);
                }
            }
        }

        return allSucceeded;
    }

    private static boolean isNativeMatch(RedactionMatch m, ExtractedPageData pageData) {
        int localStart = m.getStartOffset() - pageData.globalNativeOffsetStart;
        int localEnd = m.getEndOffset() - pageData.globalNativeOffsetStart;
        return localStart >= 0 && localEnd <= pageData.nativeText.length() && localEnd > localStart;
    }

    private static int resolveLocalNativeStart(RedactionMatch m, ExtractedPageData pageData) {
        if (m.getStartOffset() >= pageData.globalNativeOffsetStart
                && m.getEndOffset() <= pageData.globalNativeOffsetStart + pageData.nativeText.length()) {
            return m.getStartOffset() - pageData.globalNativeOffsetStart;
        }
        if (m.getStartOffset() >= 0 && m.getEndOffset() <= pageData.nativeText.length()) {
            return m.getStartOffset();
        }
        return -1;
    }

    private static int resolveLocalNativeEnd(RedactionMatch m, ExtractedPageData pageData) {
        if (m.getStartOffset() >= pageData.globalNativeOffsetStart
                && m.getEndOffset() <= pageData.globalNativeOffsetStart + pageData.nativeText.length()) {
            return m.getEndOffset() - pageData.globalNativeOffsetStart;
        }
        if (m.getStartOffset() >= 0 && m.getEndOffset() <= pageData.nativeText.length()) {
            return m.getEndOffset();
        }
        return -1;
    }

    private static String extractRawSecretForMatch(
            RedactionMatch m,
            ExtractedPageData pageData,
            String fullConcatenatedText) {
        int localStart = resolveLocalNativeStart(m, pageData);
        int localEnd = resolveLocalNativeEnd(m, pageData);
        if (localStart >= 0 && localEnd <= pageData.nativeText.length() && localEnd > localStart) {
            return pageData.nativeText.substring(localStart, localEnd);
        }
        for (PageOcrSegment seg : pageData.ocrSegments) {
            String ocrTxt = seg.ocrResult.getExtractedText();
            int ocrStart = m.getStartOffset() - seg.globalTextOffsetStart;
            int ocrEnd = m.getEndOffset() - seg.globalTextOffsetStart;
            if (ocrStart >= 0 && ocrEnd <= ocrTxt.length() && ocrEnd > ocrStart) {
                return ocrTxt.substring(ocrStart, ocrEnd);
            }
        }
        if (m.getStartOffset() >= 0 && m.getEndOffset() <= fullConcatenatedText.length()
                && m.getEndOffset() > m.getStartOffset()) {
            return fullConcatenatedText.substring(m.getStartOffset(), m.getEndOffset());
        }
        return "";
    }

    /**
     * Rewrites a PDF content stream to permanently excise deleted character indices from
     * text-showing operators ({@code Tj}, {@code TJ}, {@code '}, {@code "}), replacing removed
     * interior spans with PDF {@code TJ} kerning shifts so unselected text stays at its exact coordinate.
     */
    private static String rewriteStreamRemovingCharacters(
            String streamContent,
            Map<Integer, Set<Integer>> operatorDeletions,
            Iterable<String> fallbackRawSecrets) {
        if (streamContent == null || streamContent.isEmpty()) {
            return "";
        }

        // Tokenize and rewrite text-showing operators in exact order of operatorId
        Pattern textOpPattern = Pattern.compile(
                "(\\((?:\\\\.|[^\\\\()])*\\)|<[0-9A-Fa-f\\s]*>)\\s*(Tj|')|\\[((?:\\\\.|[^\\[\\]])*)\\]\\s*(TJ)");
        Matcher matcher = textOpPattern.matcher(streamContent);
        StringBuilder rewritten = new StringBuilder();
        int opId = 0;

        while (matcher.find()) {
            int currentOpId = opId++;
            Set<Integer> delSet = operatorDeletions.get(currentOpId);

            if (matcher.group(1) != null) {
                // Single string operator: (...) Tj or <...> Tj or (...) '
                String rawToken = matcher.group(1);
                String opName = matcher.group(2);
                String decoded = decodePdfStringOrHexToken(rawToken);

                Set<Integer> effectiveDeletions = (delSet != null && !delSet.isEmpty())
                        ? new HashSet<>(delSet)
                        : findFallbackSecretIndices(decoded, fallbackRawSecrets);

                if (effectiveDeletions.isEmpty()) {
                    matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group(0)));
                } else {
                    String replacementOp = buildRedactedTjArrayOperator(decoded, effectiveDeletions, "'".equals(opName));
                    matcher.appendReplacement(rewritten, Matcher.quoteReplacement(replacementOp));
                }
            } else if (matcher.group(3) != null) {
                // Array operator: [ ... ] TJ
                String arrayBody = matcher.group(3);
                String decodedFull = decodeTjArrayText(arrayBody);

                Set<Integer> effectiveDeletions = (delSet != null && !delSet.isEmpty())
                        ? new HashSet<>(delSet)
                        : findFallbackSecretIndices(decodedFull, fallbackRawSecrets);

                if (effectiveDeletions.isEmpty()) {
                    matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group(0)));
                } else {
                    String replacementOp = rewriteTjArrayRemovingIndices(arrayBody, effectiveDeletions);
                    matcher.appendReplacement(rewritten, Matcher.quoteReplacement(replacementOp));
                }
            }
        }
        matcher.appendTail(rewritten);
        return rewritten.toString();
    }

    private static Set<Integer> findFallbackSecretIndices(String decoded, Iterable<String> secrets) {
        Set<Integer> indices = new HashSet<>();
        if (decoded == null || decoded.isEmpty() || secrets == null) {
            return indices;
        }
        for (String s : secrets) {
            if (s == null || s.isBlank()) continue;
            int idx = decoded.indexOf(s);
            while (idx >= 0) {
                for (int k = idx; k < idx + s.length(); k++) {
                    indices.add(k);
                }
                idx = decoded.indexOf(s, idx + s.length());
            }
        }
        return indices;
    }

    /**
     * Converts a partially or fully redacted text string into a {@code [...] TJ} operator where
     * deleted characters are excised and replaced by a negative kerning displacement {@code -W}
     * (in 1/1000 em units) so subsequent non-sensitive text on the same line does not shift!
     */
    private static String buildRedactedTjArrayOperator(
            String decoded,
            Set<Integer> deletedIndices,
            boolean moveNextLineFirst) {
        StringBuilder out = new StringBuilder();
        if (moveNextLineFirst) {
            out.append("T* ");
        }
        out.append("[");
        StringBuilder keptRun = new StringBuilder();
        int deletedWidthThousandths = 0;

        for (int i = 0; i < decoded.length(); i++) {
            char ch = decoded.charAt(i);
            if (deletedIndices.contains(i)) {
                if (keptRun.length() > 0) {
                    out.append("(").append(escapePdfString(keptRun.toString())).append(") ");
                    keptRun.setLength(0);
                }
                deletedWidthThousandths += estimateCharWidthThousandths(ch);
            } else {
                if (deletedWidthThousandths > 0) {
                    out.append("-").append(deletedWidthThousandths).append(" ");
                    deletedWidthThousandths = 0;
                }
                keptRun.append(ch);
            }
        }
        if (keptRun.length() > 0) {
            out.append("(").append(escapePdfString(keptRun.toString())).append(")");
        } else if (deletedWidthThousandths > 0) {
            out.append("-").append(deletedWidthThousandths);
        }
        out.append("] TJ");
        return out.toString();
    }

    private static String rewriteTjArrayRemovingIndices(String arrayBody, Set<Integer> deletedIndices) {
        Pattern elemPattern = Pattern.compile("(\\((?:\\\\.|[^\\\\()])*\\)|<[0-9A-Fa-f\\s]*>)|(-?\\d+(?:\\.\\d+)?)");
        Matcher m = elemPattern.matcher(arrayBody);
        StringBuilder out = new StringBuilder("[");
        int globalCharIdx = 0;

        while (m.find()) {
            if (m.group(1) != null) {
                String subStr = decodePdfStringOrHexToken(m.group(1));
                StringBuilder keptRun = new StringBuilder();
                int delWidth = 0;

                for (int i = 0; i < subStr.length(); i++) {
                    char ch = subStr.charAt(i);
                    int cIdx = globalCharIdx++;
                    if (deletedIndices.contains(cIdx)) {
                        if (keptRun.length() > 0) {
                            out.append("(").append(escapePdfString(keptRun.toString())).append(") ");
                            keptRun.setLength(0);
                        }
                        delWidth += estimateCharWidthThousandths(ch);
                    } else {
                        if (delWidth > 0) {
                            out.append("-").append(delWidth).append(" ");
                            delWidth = 0;
                        }
                        keptRun.append(ch);
                    }
                }
                if (keptRun.length() > 0) {
                    out.append("(").append(escapePdfString(keptRun.toString())).append(") ");
                }
                if (delWidth > 0) {
                    out.append("-").append(delWidth).append(" ");
                }
            } else if (m.group(2) != null) {
                out.append(m.group(2)).append(" ");
            }
        }
        out.append("] TJ");
        return out.toString();
    }

    private static String appendOpaqueRedactionRectangles(
            String streamContent,
            List<PdfBoundingBox> boxes,
            ExtractedPageData pageData) {
        StringBuilder sb = new StringBuilder(streamContent);
        if (!streamContent.endsWith("\n")) {
            sb.append("\n");
        }
        sb.append("q\n0 0 0 rg\n");
        for (PdfBoundingBox box : boxes) {
            if (box == null || !box.isValid()) continue;
            sb.append(String.format(Locale.ROOT, "%.2f %.2f %.2f %.2f re f\n",
                    box.getX(), box.getY(), box.getWidth(), box.getHeight()));
        }
        sb.append("Q\n");
        return sb.toString();
    }

    /**
     * Paints permanent opaque black rectangles over every target {@link PdfBoundingBox} in the image.
     */
    private static BufferedImage createRedactedImageCopy(
            BufferedImage source,
            List<PdfBoundingBox> boxes,
            PdfBoundingBox placementBox) {
        int w = source.getWidth();
        int h = source.getHeight();
        BufferedImage redacted = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = redacted.createGraphics();
        g2.drawImage(source, 0, 0, null);
        g2.setColor(Color.BLACK);

        for (PdfBoundingBox box : boxes) {
            if (box == null || !box.isValid()) continue;
            Rectangle pixelRect = box.toPixelRect(w, h, placementBox, 3);
            g2.fillRect(pixelRect.x, pixelRect.y, pixelRect.width, pixelRect.height);
        }
        g2.dispose();
        return redacted;
    }

    /**
     * Replaces a PDF {@code /Subtype /Image} XObject with a newly encoded lossless Flate-compressed
     * RGB raster stream, permanently discarding the original unredacted image bytes.
     */
    private static void replacePdfImageObjectPermanently(PdfObject imgObj, BufferedImage redactedImg) {
        int w = redactedImg.getWidth();
        int h = redactedImg.getHeight();
        byte[] rawRgb = new byte[w * h * 3];
        int idx = 0;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int rgb = redactedImg.getRGB(x, y);
                rawRgb[idx++] = (byte) ((rgb >> 16) & 0xFF);
                rawRgb[idx++] = (byte) ((rgb >> 8) & 0xFF);
                rawRgb[idx++] = (byte) (rgb & 0xFF);
            }
        }
        byte[] compressed = compressFlate(rawRgb);
        imgObj.hasStream = true;
        imgObj.isFlateCompressed = true;
        imgObj.rawStreamBytes = compressed;
        imgObj.streamContent = null;
        imgObj.dictionary = "<< /Type /XObject /Subtype /Image /Width " + w
                + " /Height " + h
                + " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length "
                + compressed.length + " >>";
    }

    private static void scrubDocumentMetadataDictionaries(
            PdfParsedDocument doc,
            Iterable<String> rawSecrets,
            List<RedactionMatch> selectedMatches) {
        for (PdfObject obj : doc.objects) {
            if (obj.dictionary == null || obj.dictionary.isEmpty()) continue;
            for (String secret : rawSecrets) {
                if (secret != null && !secret.isBlank() && obj.dictionary.contains(secret)) {
                    obj.dictionary = obj.dictionary.replace(secret, "[REDACTED]");
                }
            }
            for (RedactionMatch m : selectedMatches) {
                if (m.getReplacementToken() != null && !obj.dictionary.isEmpty()) {
                    // Scrub /Title, /Author, /Subject, /Keywords if they contain sensitive values
                }
            }
        }
    }

    // =========================================================================
    // Stage 5: Independent Post-Redaction Verification
    // =========================================================================

    private record PostVerificationOutcome(
            VerificationStatus status,
            String report,
            List<String> warnings) {}

    /**
     * Reopens the saved output PDF from disk and performs independent text and image pixel checks.
     */
    private PostVerificationOutcome verifySavedPdfIndependently(
            Path savedPdfPath,
            List<RedactionMatch> appliedMatches,
            Map<String, String> matchIdToRawSecret,
            int skippedMatchesCount) throws DocumentProcessingException {
        byte[] savedBytes = readPdfBytes(savedPdfPath);
        PdfParsedDocument reloadedDoc = parsePdf(savedBytes, savedPdfPath.getFileName().toString());
        boolean hasOcrMatches = appliedMatches.stream().anyMatch(
                m -> m.getDetectionMethod() == DetectionMethod.OCR || m.getDetectionMethod() == DetectionMethod.HYBRID);
        ExtractedDocumentData reloadedData = extractDocumentPages(reloadedDoc, savedPdfPath, hasOcrMatches);

        List<String> failures = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        String normFullOutputText = normalizeForLeakCheck(reloadedData.fullConcatenatedText);

        for (RedactionMatch m : appliedMatches) {
            String rawSecret = matchIdToRawSecret.getOrDefault(m.getMatchId(), "");
            int pageNum = m.getPageNumber();
            ExtractedPageData reloadedPage = (pageNum >= 1 && pageNum <= reloadedData.pages.size())
                    ? reloadedData.pages.get(pageNum - 1)
                    : null;

            // 1. Text leak verification
            if (!rawSecret.isBlank()) {
                if (reloadedData.fullConcatenatedText.contains(rawSecret)) {
                    failures.add("Match " + m.getMatchId() + " (" + m.getCandidateType()
                            + ", preview=" + m.getMaskedPreview() + ") remained extractable in output text on page " + pageNum);
                } else {
                    String normSecret = normalizeForLeakCheck(rawSecret);
                    if (normSecret.length() >= 5 && normFullOutputText.contains(normSecret)) {
                        failures.add("Match " + m.getMatchId() + " (" + m.getCandidateType()
                                + ", preview=" + m.getMaskedPreview() + ") remained detectable in normalized output text");
                    }
                }

                // Also verify raw decompressed content streams do not contain the raw secret
                for (PdfObject obj : reloadedDoc.objects) {
                    if (obj.streamContent != null && obj.streamContent.contains(rawSecret)) {
                        failures.add("Match " + m.getMatchId() + " (" + m.getCandidateType()
                                + ") remained present in raw PDF stream object " + obj.objNumber);
                    }
                }
            }

            // 2. Image pixel verification for OCR / image matches
            if (m.getDetectionMethod() == DetectionMethod.OCR || m.getDetectionMethod() == DetectionMethod.HYBRID) {
                if (reloadedPage != null && !reloadedPage.images.isEmpty()) {
                    for (PdfBoundingBox box : m.getBoundingBoxes()) {
                        for (ExtractedPageImage outImg : reloadedPage.images) {
                            Rectangle coreRect = box.toPixelRect(
                                    outImg.image.getWidth(), outImg.image.getHeight(), outImg.placementBox, 0);
                            if (!isImageRegionPermanentlyBlackened(outImg.image, coreRect)) {
                                failures.add("Image verification failed for match " + m.getMatchId()
                                        + " on page " + pageNum + ": unredacted non-black pixels remain in target bounding box");
                            }
                        }
                    }
                }
            }
        }

        if (!failures.isEmpty()) {
            String failReport = "Verification Status: FAILED. " + String.join("; ", failures)
                    + " | " + RedactionResult.VERIFICATION_DISCLAIMER;
            return new PostVerificationOutcome(VerificationStatus.FAILED, failReport, failures);
        }

        if (skippedMatchesCount > 0 || (appliedMatches.isEmpty() && skippedMatchesCount > 0)) {
            warnings.add(skippedMatchesCount + " detected candidate(s) were skipped by user selection and remain in the document.");
            String partialReport = "Verification Status: PARTIAL. All " + appliedMatches.size()
                    + " selected redaction(s) passed independent text and image verification checks, "
                    + "but " + skippedMatchesCount + " candidate(s) were skipped. "
                    + RedactionResult.VERIFICATION_DISCLAIMER;
            return new PostVerificationOutcome(VerificationStatus.PARTIAL, partialReport, warnings);
        }

        String verifiedReport = "Verification Status: VERIFIED. Reopened saved PDF and verified that all "
                + appliedMatches.size() + " redacted item(s) were permanently removed from text streams and/or "
                + "opaque-redacted in page images with no retained unredacted layers. "
                + RedactionResult.VERIFICATION_DISCLAIMER;
        return new PostVerificationOutcome(VerificationStatus.VERIFIED, verifiedReport, warnings);
    }

    private static boolean isImageRegionPermanentlyBlackened(BufferedImage img, Rectangle rect) {
        int x0 = Math.max(0, rect.x);
        int y0 = Math.max(0, rect.y);
        int x1 = Math.min(img.getWidth(), rect.x + rect.width);
        int y1 = Math.min(img.getHeight(), rect.y + rect.height);
        if (x1 <= x0 || y1 <= y0) {
            return false;
        }
        int nonBlackPixels = 0;
        int totalPixels = (x1 - x0) * (y1 - y0);
        for (int y = y0; y < y1; y++) {
            for (int x = x0; x < x1; x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                if (r > 10 || g > 10 || b > 10) {
                    nonBlackPixels++;
                }
            }
        }
        return nonBlackPixels == 0 && totalPixels > 0;
    }

    private static String normalizeForLeakCheck(String s) {
        if (s == null || s.isEmpty()) return "";
        return s.replaceAll("[\\s\\-\\r\\n]+", "").toLowerCase(Locale.ROOT);
    }

    // =========================================================================
    // Page-by-Page Extraction & Coordinate Mapping Data Structures
    // =========================================================================

    private record CharOrigin(
            int pageNumber,
            char ch,
            PdfBoundingBox boundingBox,
            int streamObjNum,
            int operatorId,
            int charIdxInOperator) {}

    private static final class ExtractedPageImage {
        final PdfObject pdfObject;
        final String xObjectName;
        BufferedImage image;
        final PdfBoundingBox placementBox;

        ExtractedPageImage(PdfObject pdfObject, String xObjectName, BufferedImage image, PdfBoundingBox placementBox) {
            this.pdfObject = pdfObject;
            this.xObjectName = xObjectName;
            this.image = image;
            this.placementBox = placementBox;
        }
    }

    private record PageOcrSegment(
            ExtractedPageImage sourceImage,
            OcrExtractionResult ocrResult,
            int globalTextOffsetStart) {}

    private static final class ExtractedPageData {
        final int pageNumber;
        final PdfObject pageObject;
        final double widthPts;
        final double heightPts;
        final int rotationDegrees;
        final List<Integer> contentStreamObjNums;
        final String nativeText;
        final List<CharOrigin> charOrigins;
        final int globalNativeOffsetStart;
        final boolean hasNativeText;
        final List<ExtractedPageImage> images;
        final List<PageOcrSegment> ocrSegments;
        final PageExtractionReport report;

        ExtractedPageData(
                int pageNumber,
                PdfObject pageObject,
                double widthPts,
                double heightPts,
                int rotationDegrees,
                List<Integer> contentStreamObjNums,
                String nativeText,
                List<CharOrigin> charOrigins,
                int globalNativeOffsetStart,
                List<ExtractedPageImage> images,
                List<PageOcrSegment> ocrSegments,
                PageExtractionReport report) {
            this.pageNumber = pageNumber;
            this.pageObject = pageObject;
            this.widthPts = widthPts;
            this.heightPts = heightPts;
            this.rotationDegrees = rotationDegrees;
            this.contentStreamObjNums = contentStreamObjNums;
            this.nativeText = nativeText;
            this.charOrigins = charOrigins;
            this.globalNativeOffsetStart = globalNativeOffsetStart;
            this.hasNativeText = !nativeText.isBlank();
            this.images = images;
            this.ocrSegments = ocrSegments;
            this.report = report;
        }
    }

    private static final class ExtractedDocumentData {
        final int totalPages;
        final int pagesProcessed;
        final int pagesFailed;
        final int nativePages;
        final int ocrPages;
        final int emptyPages;
        final int ocrUnavailablePages;
        final int lowConfidenceOcrPages;
        final String firstErrorMessage;
        final String fullConcatenatedText;
        final List<ExtractedPageData> pages;
        final List<PageExtractionReport> pageReports;

        ExtractedDocumentData(
                int totalPages,
                int pagesProcessed,
                int pagesFailed,
                int nativePages,
                int ocrPages,
                int emptyPages,
                int ocrUnavailablePages,
                int lowConfidenceOcrPages,
                String firstErrorMessage,
                String fullConcatenatedText,
                List<ExtractedPageData> pages,
                List<PageExtractionReport> pageReports) {
            this.totalPages = totalPages;
            this.pagesProcessed = pagesProcessed;
            this.pagesFailed = pagesFailed;
            this.nativePages = nativePages;
            this.ocrPages = ocrPages;
            this.emptyPages = emptyPages;
            this.ocrUnavailablePages = ocrUnavailablePages;
            this.lowConfidenceOcrPages = lowConfidenceOcrPages;
            this.firstErrorMessage = firstErrorMessage;
            this.fullConcatenatedText = fullConcatenatedText;
            this.pages = pages;
            this.pageReports = pageReports;
        }
    }

    private ExtractedDocumentData extractDocumentPages(
            PdfParsedDocument doc,
            Path sourcePath,
            boolean runOcrOnImages) throws DocumentProcessingException {
        List<ResolvedPageNode> pageNodes = resolvePageTree(doc);
        if (pageNodes.isEmpty()) {
            throw new DocumentProcessingException(
                    "Malformed or unreadable PDF: no page objects found in " + sourcePath.getFileName());
        }

        StringBuilder fullTextBuilder = new StringBuilder();
        List<ExtractedPageData> extractedPages = new ArrayList<>();
        List<PageExtractionReport> reports = new ArrayList<>();

        int pagesProcessed = 0;
        int pagesFailed = 0;
        int nativePages = 0;
        int ocrPages = 0;
        int emptyPages = 0;
        int ocrUnavailablePages = 0;
        int lowConfPages = 0;
        String firstError = "";

        for (int i = 0; i < pageNodes.size(); i++) {
            ResolvedPageNode node = pageNodes.get(i);
            int pageNum = i + 1;
            double pageW = node.widthPts;
            double pageH = node.heightPts;
            int rotation = node.rotationDegrees;

            boolean streamFailure = false;
            String streamErrorMsg = "";

            // 1. Collect content streams for this page
            List<Integer> streamNums = resolvePageContentStreamNumbers(doc, node.pageObj);
            List<GlyphFragment> pageFragments = new ArrayList<>();
            Map<String, PdfBoundingBox> xObjectPlacements = new HashMap<>();

            for (int sObjNum : streamNums) {
                PdfObject sObj = doc.getObjectByNumber(sObjNum);
                if (sObj == null) {
                    streamFailure = true;
                    streamErrorMsg = "Missing content stream object " + sObjNum;
                    break;
                }
                if (sObj.streamDecompressionFailed) {
                    streamFailure = true;
                    streamErrorMsg = "Corrupted compressed stream in object " + sObjNum;
                    break;
                }
                if (sObj.streamContent != null && !sObj.streamContent.isEmpty()) {
                    interpretContentStream(
                            sObj.streamContent,
                            sObjNum,
                            pageNum,
                            pageW,
                            pageH,
                            rotation,
                            pageFragments,
                            xObjectPlacements);
                }
            }

            // 2. Assemble reading-order native text & character coordinate origins
            AssembledPageText assembled = assemblePageTextInReadingOrder(pageFragments, pageNum, pageW, pageH, rotation);
            int globalNativeStart = fullTextBuilder.length();
            if (!assembled.text.isEmpty()) {
                fullTextBuilder.append(assembled.text).append('\n');
            }

            // 3. Extract embedded /Subtype /Image XObjects on this page
            List<ExtractedPageImage> pageImages = new ArrayList<>();
            List<Integer> imageObjNums = resolvePageImageObjectNumbers(doc, node.pageObj, node.inheritedResources);
            for (int imgObjNum : imageObjNums) {
                PdfObject imgObj = doc.getObjectByNumber(imgObjNum);
                if (imgObj == null) {
                    streamFailure = true;
                    streamErrorMsg = "Missing image XObject " + imgObjNum;
                    continue;
                }
                if (imgObj.streamDecompressionFailed) {
                    streamFailure = true;
                    streamErrorMsg = "Corrupted image stream in object " + imgObjNum;
                    continue;
                }
                BufferedImage decodedImg = decodePdfImageObject(imgObj);
                if (decodedImg == null) {
                    streamFailure = true;
                    streamErrorMsg = "Undecodable image stream in object " + imgObjNum;
                } else {
                    String xName = findXObjectNameForObjNum(node.pageObj.dictionary + " " + node.inheritedResources, imgObjNum);
                    PdfBoundingBox placement = xObjectPlacements.getOrDefault(
                            xName,
                            new PdfBoundingBox(pageNum, 0, 0, pageW, pageH, pageW, pageH, rotation));
                    pageImages.add(new ExtractedPageImage(imgObj, xName, decodedImg, placement));
                }
            }

            // 4. Run OCR if page has scanned/embedded images
            List<PageOcrSegment> ocrSegments = new ArrayList<>();
            boolean ocrAttempted = false;
            boolean ocrSucceeded = false;
            boolean pageOcrUnavailable = false;
            double avgOcrConf = -1.0;
            String ocrDiag = "";

            if (runOcrOnImages && !pageImages.isEmpty()) {
                ocrAttempted = true;
                double confSum = 0.0;
                int confCount = 0;

                for (ExtractedPageImage pageImg : pageImages) {
                    OcrExtractionResult ocrRes = ocrEngine.recognizeImage(
                            pageImg.image,
                            pageNum,
                            pageImg.placementBox,
                            pageW,
                            pageH,
                            rotation);
                    if (ocrRes.isOcrUnavailable()) {
                        pageOcrUnavailable = true;
                        ocrDiag = ocrRes.getDiagnosticMessage();
                    } else if (!ocrRes.isSuccess()) {
                        streamFailure = true;
                        streamErrorMsg = ocrRes.getDiagnosticMessage();
                    } else {
                        ocrSucceeded = true;
                        int globalOcrStart = fullTextBuilder.length();
                        if (!ocrRes.getExtractedText().isEmpty()) {
                            fullTextBuilder.append(ocrRes.getExtractedText()).append('\n');
                        }
                        ocrSegments.add(new PageOcrSegment(pageImg, ocrRes, globalOcrStart));
                        if (ocrRes.getAverageConfidence() >= 0) {
                            confSum += ocrRes.getAverageConfidence();
                            confCount++;
                        }
                        ocrDiag = ocrRes.getDiagnosticMessage();
                    }
                }
                if (confCount > 0) {
                    avgOcrConf = confSum / confCount;
                }
            }

            boolean hasNative = !assembled.text.isBlank();
            boolean hasImages = !pageImages.isEmpty();
            int totalCharsOnPage = assembled.text.length()
                    + ocrSegments.stream().mapToInt(s -> s.ocrResult.getExtractedText().length()).sum();

            PageStatus status;
            String diagMsg;

            if (streamFailure) {
                status = PageStatus.EXTRACTION_FAILED;
                diagMsg = streamErrorMsg;
                pagesFailed++;
                if (firstError.isEmpty()) firstError = streamErrorMsg;
            } else if (pageOcrUnavailable) {
                status = PageStatus.OCR_UNAVAILABLE;
                diagMsg = ocrDiag;
                ocrUnavailablePages++;
                if (hasNative) {
                    pagesProcessed++;
                    nativePages++;
                }
            } else if (hasNative && ocrSucceeded) {
                if (avgOcrConf >= 0 && avgOcrConf < config.getMinOcrConfidence()) {
                    status = PageStatus.LOW_CONFIDENCE_OCR;
                    lowConfPages++;
                } else {
                    status = PageStatus.HYBRID_EXTRACTED;
                }
                diagMsg = "Native text (" + assembled.text.length() + " chars) + " + ocrDiag;
                pagesProcessed++;
                nativePages++;
                ocrPages++;
            } else if (ocrSucceeded) {
                if (avgOcrConf >= 0 && avgOcrConf < config.getMinOcrConfidence()) {
                    status = PageStatus.LOW_CONFIDENCE_OCR;
                    lowConfPages++;
                } else {
                    status = PageStatus.OCR_EXTRACTED;
                }
                diagMsg = ocrDiag;
                pagesProcessed++;
                ocrPages++;
            } else if (hasNative) {
                status = PageStatus.NATIVE_TEXT_EXTRACTED;
                diagMsg = "Extracted " + assembled.text.length() + " selectable character(s)";
                pagesProcessed++;
                nativePages++;
            } else {
                status = PageStatus.EMPTY_PAGE;
                diagMsg = "Blank/empty page (0 text operators, 0 images)";
                pagesProcessed++;
                emptyPages++;
            }

            PageExtractionReport pageReport = new PageExtractionReport(
                    pageNum,
                    status,
                    hasNative,
                    hasImages,
                    ocrAttempted,
                    ocrSucceeded,
                    avgOcrConf,
                    totalCharsOnPage,
                    rotation,
                    pageW,
                    pageH,
                    diagMsg);

            reports.add(pageReport);
            extractedPages.add(new ExtractedPageData(
                    pageNum,
                    node.pageObj,
                    pageW,
                    pageH,
                    rotation,
                    streamNums,
                    assembled.text,
                    assembled.charOrigins,
                    globalNativeStart,
                    pageImages,
                    ocrSegments,
                    pageReport));
        }

        return new ExtractedDocumentData(
                pageNodes.size(),
                pagesProcessed,
                pagesFailed,
                nativePages,
                ocrPages,
                emptyPages,
                ocrUnavailablePages,
                lowConfPages,
                firstError,
                fullTextBuilder.toString(),
                extractedPages,
                reports);
    }

    /**
     * Maps a character offset span {@code [startOffset, endOffset)} in a page's native text
     * to tight, line-grouped {@link PdfBoundingBox}es using exact character positions.
     */
    private static List<PdfBoundingBox> mapNativeTextSpanToBoxes(
            ExtractedPageData pageData,
            int startOffset,
            int endOffset) {
        int clampedStart = Math.max(0, startOffset);
        int clampedEnd = Math.min(pageData.charOrigins.size(), endOffset);
        if (clampedEnd <= clampedStart) {
            return List.of();
        }

        List<PdfBoundingBox> charBoxes = new ArrayList<>();
        for (int i = clampedStart; i < clampedEnd; i++) {
            CharOrigin origin = pageData.charOrigins.get(i);
            if (origin != null && origin.boundingBox != null && origin.boundingBox.isValid()) {
                charBoxes.add(origin.boundingBox);
            }
        }

        if (charBoxes.isEmpty()) {
            return List.of();
        }

        // Merge adjacent character boxes on the same line, keeping separate boxes for multi-line matches
        List<PdfBoundingBox> mergedLines = new ArrayList<>();
        PdfBoundingBox currentLineBox = charBoxes.get(0);
        for (int i = 1; i < charBoxes.size(); i++) {
            PdfBoundingBox nextBox = charBoxes.get(i);
            double maxGap = Math.max(24.0, currentLineBox.getHeight() * 2.2);
            if (currentLineBox.canMergeOnSameLine(nextBox, maxGap)) {
                currentLineBox = currentLineBox.union(nextBox);
            } else {
                mergedLines.add(currentLineBox);
                currentLineBox = nextBox;
            }
        }
        mergedLines.add(currentLineBox);
        return Collections.unmodifiableList(mergedLines);
    }

    // =========================================================================
    // PDF Content Stream Graphics & Text State Interpreter
    // =========================================================================

    private record GlyphFragment(
            char ch,
            double x,
            double y,
            double width,
            double height,
            int streamObjNum,
            int operatorId,
            int charIdxInOp) {}

    private record AssembledPageText(String text, List<CharOrigin> charOrigins) {}

    private static void interpretContentStream(
            String streamContent,
            int streamObjNum,
            int pageNumber,
            double pageWidthPts,
            double pageHeightPts,
            int rotationDegrees,
            List<GlyphFragment> outFragments,
            Map<String, PdfBoundingBox> outXObjectPlacements) {

        // Graphics state CTM [a b c d e f]
        double[] ctm = {1, 0, 0, 1, 0, 0};
        List<double[]> ctmStack = new ArrayList<>();

        // Text state
        double[] tm = {1, 0, 0, 1, 0, 0};
        double[] tlm = {1, 0, 0, 1, 0, 0};
        double fontSize = 12.0;
        double leading = 14.0;
        double charSpacing = 0.0;
        double wordSpacing = 0.0;
        double horizScale = 1.0;

        // First scan for text operators to keep exact operatorId alignment with rewriteStreamRemovingCharacters
        // while also tracking positioning operators in stream order
        List<String> tokens = tokenizePdfContentStream(streamContent);
        List<String> operandStack = new ArrayList<>();
        int textOpSequence = 0;

        for (String tok : tokens) {
            switch (tok) {
                case "q" -> {
                    ctmStack.add(ctm.clone());
                    operandStack.clear();
                }
                case "Q" -> {
                    if (!ctmStack.isEmpty()) {
                        ctm = ctmStack.remove(ctmStack.size() - 1);
                    }
                    operandStack.clear();
                }
                case "cm" -> {
                    if (operandStack.size() >= 6) {
                        int n = operandStack.size();
                        double a = parseDoubleSafe(operandStack.get(n - 6), 1);
                        double b = parseDoubleSafe(operandStack.get(n - 5), 0);
                        double c = parseDoubleSafe(operandStack.get(n - 4), 0);
                        double d = parseDoubleSafe(operandStack.get(n - 3), 1);
                        double e = parseDoubleSafe(operandStack.get(n - 2), 0);
                        double f = parseDoubleSafe(operandStack.get(n - 1), 0);
                        ctm = multiplyMatrix(new double[]{a, b, c, d, e, f}, ctm);
                    }
                    operandStack.clear();
                }
                case "Do" -> {
                    if (!operandStack.isEmpty()) {
                        String xName = operandStack.get(operandStack.size() - 1);
                        double imgW = Math.max(1.0, Math.hypot(ctm[0], ctm[1]));
                        double imgH = Math.max(1.0, Math.hypot(ctm[2], ctm[3]));
                        double imgX = ctm[4];
                        double imgY = ctm[5];
                        if (imgW <= 2.0 && imgH <= 2.0) {
                            imgW = pageWidthPts;
                            imgH = pageHeightPts;
                        }
                        outXObjectPlacements.put(xName, new PdfBoundingBox(
                                pageNumber, imgX, imgY, imgW, imgH, pageWidthPts, pageHeightPts, rotationDegrees));
                    }
                    operandStack.clear();
                }
                case "BT" -> {
                    tm = new double[]{1, 0, 0, 1, 0, 0};
                    tlm = new double[]{1, 0, 0, 1, 0, 0};
                    operandStack.clear();
                }
                case "ET" -> operandStack.clear();
                case "Tf" -> {
                    if (operandStack.size() >= 2) {
                        double sz = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 12.0);
                        if (Math.abs(sz) > 0.01) {
                            fontSize = Math.abs(sz);
                        }
                    }
                    operandStack.clear();
                }
                case "TL" -> {
                    if (!operandStack.isEmpty()) {
                        leading = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 14.0);
                    }
                    operandStack.clear();
                }
                case "Tc" -> {
                    if (!operandStack.isEmpty()) {
                        charSpacing = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 0.0);
                    }
                    operandStack.clear();
                }
                case "Tw" -> {
                    if (!operandStack.isEmpty()) {
                        wordSpacing = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 0.0);
                    }
                    operandStack.clear();
                }
                case "Tz" -> {
                    if (!operandStack.isEmpty()) {
                        horizScale = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 100.0) / 100.0;
                    }
                    operandStack.clear();
                }
                case "Td" -> {
                    if (operandStack.size() >= 2) {
                        double tx = parseDoubleSafe(operandStack.get(operandStack.size() - 2), 0.0);
                        double ty = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 0.0);
                        tlm = multiplyMatrix(new double[]{1, 0, 0, 1, tx, ty}, tlm);
                        tm = tlm.clone();
                    }
                    operandStack.clear();
                }
                case "TD" -> {
                    if (operandStack.size() >= 2) {
                        double tx = parseDoubleSafe(operandStack.get(operandStack.size() - 2), 0.0);
                        double ty = parseDoubleSafe(operandStack.get(operandStack.size() - 1), 0.0);
                        leading = -ty;
                        tlm = multiplyMatrix(new double[]{1, 0, 0, 1, tx, ty}, tlm);
                        tm = tlm.clone();
                    }
                    operandStack.clear();
                }
                case "Tm" -> {
                    if (operandStack.size() >= 6) {
                        int n = operandStack.size();
                        double a = parseDoubleSafe(operandStack.get(n - 6), 1);
                        double b = parseDoubleSafe(operandStack.get(n - 5), 0);
                        double c = parseDoubleSafe(operandStack.get(n - 4), 0);
                        double d = parseDoubleSafe(operandStack.get(n - 3), 1);
                        double e = parseDoubleSafe(operandStack.get(n - 2), 0);
                        double f = parseDoubleSafe(operandStack.get(n - 1), 0);
                        tm = new double[]{a, b, c, d, e, f};
                        tlm = tm.clone();
                    }
                    operandStack.clear();
                }
                case "T*" -> {
                    tlm = multiplyMatrix(new double[]{1, 0, 0, 1, 0, -leading}, tlm);
                    tm = tlm.clone();
                    operandStack.clear();
                }
                case "Tj", "'" -> {
                    if ("'".equals(tok)) {
                        tlm = multiplyMatrix(new double[]{1, 0, 0, 1, 0, -leading}, tlm);
                        tm = tlm.clone();
                    }
                    if (!operandStack.isEmpty()) {
                        String strTok = operandStack.get(operandStack.size() - 1);
                        if (strTok.startsWith("(") || strTok.startsWith("<")) {
                            int opId = textOpSequence++;
                            String decoded = decodePdfStringOrHexToken(strTok);
                            emitGlyphFragmentsForString(
                                    decoded,
                                    0,
                                    tm,
                                    ctm,
                                    fontSize,
                                    charSpacing,
                                    wordSpacing,
                                    horizScale,
                                    pageWidthPts,
                                    pageHeightPts,
                                    rotationDegrees,
                                    streamObjNum,
                                    opId,
                                    outFragments);
                        }
                    }
                    operandStack.clear();
                }
                case "TJ" -> {
                    if (!operandStack.isEmpty()) {
                        String arrTok = operandStack.get(operandStack.size() - 1);
                        if (arrTok.startsWith("[")) {
                            int opId = textOpSequence++;
                            String inner = arrTok.substring(1, arrTok.length() - 1);
                            emitGlyphFragmentsForTjArray(
                                    inner,
                                    tm,
                                    ctm,
                                    fontSize,
                                    charSpacing,
                                    wordSpacing,
                                    horizScale,
                                    pageWidthPts,
                                    pageHeightPts,
                                    rotationDegrees,
                                    streamObjNum,
                                    opId,
                                    outFragments);
                        }
                    }
                    operandStack.clear();
                }
                default -> operandStack.add(tok);
            }
        }
    }

    private static void emitGlyphFragmentsForString(
            String decoded,
            int startCharIndexInOp,
            double[] tm,
            double[] ctm,
            double fontSize,
            double charSpacing,
            double wordSpacing,
            double horizScale,
            double pageW,
            double pageH,
            int rotationDegrees,
            int streamObjNum,
            int opId,
            List<GlyphFragment> outFragments) {
        double scale = Math.hypot(tm[0], tm[1]);
        double effectiveFontSize = (scale > 0.1) ? (fontSize * scale) : fontSize;
        if (effectiveFontSize < 4.0) {
            effectiveFontSize = 11.0;
        }

        for (int i = 0; i < decoded.length(); i++) {
            char ch = decoded.charAt(i);
            double charW = (estimateCharWidthThousandths(ch) / 1000.0) * effectiveFontSize * horizScale;
            double charH = effectiveFontSize * 1.15;

            double[] combined = multiplyMatrix(tm, ctm);
            double rawX = combined[4];
            double rawY = combined[5];

            outFragments.add(new GlyphFragment(
                    ch,
                    rawX,
                    rawY,
                    charW,
                    charH,
                    streamObjNum,
                    opId,
                    startCharIndexInOp + i));

            double advance = (estimateCharWidthThousandths(ch) / 1000.0) * fontSize + charSpacing
                    + (ch == ' ' ? wordSpacing : 0.0);
            advance *= horizScale;
            tm[4] += advance * tm[0];
            tm[5] += advance * tm[1];
        }
    }

    private static void emitGlyphFragmentsForTjArray(
            String arrayInner,
            double[] tm,
            double[] ctm,
            double fontSize,
            double charSpacing,
            double wordSpacing,
            double horizScale,
            double pageW,
            double pageH,
            int rotationDegrees,
            int streamObjNum,
            int opId,
            List<GlyphFragment> outFragments) {
        Pattern elemPattern = Pattern.compile("(\\((?:\\\\.|[^\\\\()])*\\)|<[0-9A-Fa-f\\s]*>)|(-?\\d+(?:\\.\\d+)?)");
        Matcher m = elemPattern.matcher(arrayInner);
        int charIdxInOp = 0;

        while (m.find()) {
            if (m.group(1) != null) {
                String sub = decodePdfStringOrHexToken(m.group(1));
                emitGlyphFragmentsForString(
                        sub,
                        charIdxInOp,
                        tm,
                        ctm,
                        fontSize,
                        charSpacing,
                        wordSpacing,
                        horizScale,
                        pageW,
                        pageH,
                        rotationDegrees,
                        streamObjNum,
                        opId,
                        outFragments);
                charIdxInOp += sub.length();
            } else if (m.group(2) != null) {
                double kern = parseDoubleSafe(m.group(2), 0.0);
                double shift = (-kern / 1000.0) * fontSize * horizScale;
                tm[4] += shift * tm[0];
                tm[5] += shift * tm[1];
            }
        }
    }

    private static AssembledPageText assemblePageTextInReadingOrder(
            List<GlyphFragment> fragments,
            int pageNum,
            double pageW,
            double pageH,
            int rotation) {
        if (fragments.isEmpty()) {
            return new AssembledPageText("", List.of());
        }

        // Group fragments into lines by vertical Y proximity (top-to-bottom in PDF user space: higher Y is higher on page)
        List<List<GlyphFragment>> lines = new ArrayList<>();
        for (GlyphFragment g : fragments) {
            boolean placed = false;
            for (List<GlyphFragment> line : lines) {
                GlyphFragment ref = line.get(0);
                double tol = Math.max(3.5, Math.min(ref.height, g.height) * 0.45);
                if (Math.abs(g.y - ref.y) <= tol) {
                    line.add(g);
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                List<GlyphFragment> newLine = new ArrayList<>();
                newLine.add(g);
                lines.add(newLine);
            }
        }

        // Sort lines from top of page (highest Y) to bottom of page (lowest Y)
        lines.sort((a, b) -> Double.compare(b.get(0).y, a.get(0).y));

        StringBuilder sb = new StringBuilder();
        List<CharOrigin> origins = new ArrayList<>();

        for (int lineIdx = 0; lineIdx < lines.size(); lineIdx++) {
            List<GlyphFragment> line = lines.get(lineIdx);
            // Sort characters within line left-to-right ( only reordering distinct words/operators if out of order )
            line.sort((a, b) -> {
                if (a.streamObjNum == b.streamObjNum && a.operatorId == b.operatorId) {
                    return Integer.compare(a.charIdxInOp, b.charIdxInOp);
                }
                return Double.compare(a.x, b.x);
            });

            if (lineIdx > 0 && sb.length() > 0) {
                sb.append('\n');
                GlyphFragment prevEnd = lines.get(lineIdx - 1).get(lines.get(lineIdx - 1).size() - 1);
                PdfBoundingBox nlBox = new PdfBoundingBox(
                        pageNum, prevEnd.x + prevEnd.width, prevEnd.y, 2.0, prevEnd.height, pageW, pageH, rotation);
                origins.add(new CharOrigin(pageNum, '\n', nlBox, -1, -1, -1));
            }

            GlyphFragment prev = null;
            for (GlyphFragment g : line) {
                if (prev != null && prev.ch != ' ' && g.ch != ' ') {
                    double gap = g.x - (prev.x + prev.width);
                    double spaceThreshold = Math.max(2.5, prev.height * 0.28);
                    if (gap > spaceThreshold && (prev.operatorId != g.operatorId || gap > prev.height * 0.45)) {
                        sb.append(' ');
                        PdfBoundingBox spaceBox = new PdfBoundingBox(
                                pageNum, prev.x + prev.width, prev.y, gap, prev.height, pageW, pageH, rotation);
                        origins.add(new CharOrigin(pageNum, ' ', spaceBox, -1, -1, -1));
                    }
                }
                sb.append(g.ch);
                PdfBoundingBox box = new PdfBoundingBox(
                        pageNum, g.x, g.y, Math.max(1.5, g.width), Math.max(4.0, g.height), pageW, pageH, rotation);
                origins.add(new CharOrigin(pageNum, g.ch, box, g.streamObjNum, g.operatorId, g.charIdxInOp));
                prev = g;
            }
        }

        return new AssembledPageText(sb.toString(), origins);
    }

    private static double[] rotateBoxToDisplaySpace(
            double x, double y, double w, double h, double pageW, double pageH, int rotation) {
        int rot = ((rotation % 360) + 360) % 360;
        return switch (rot) {
            case 90 -> new double[]{y, pageW - x - w, h, w};
            case 180 -> new double[]{pageW - x - w, pageH - y - h, w, h};
            case 270 -> new double[]{pageH - y - h, x, h, w};
            default -> new double[]{x, y, w, h};
        };
    }

    private static double[] unrotateBoxToPageSpace(
            PdfBoundingBox box, double pageW, double pageH, int rotation) {
        int rot = ((rotation % 360) + 360) % 360;
        double x = box.getX();
        double y = box.getY();
        double w = box.getWidth();
        double h = box.getHeight();
        return switch (rot) {
            case 90 -> new double[]{pageW - y - h, x, h, w};
            case 180 -> new double[]{pageW - x - w, pageH - y - h, w, h};
            case 270 -> new double[]{y, pageH - x - w, h, w};
            default -> new double[]{x, y, w, h};
        };
    }

    private static List<String> tokenizePdfContentStream(String content) {
        List<String> tokens = new ArrayList<>();
        int len = content.length();
        int i = 0;

        while (i < len) {
            char c = content.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (c == '%') {
                while (i < len && content.charAt(i) != '\n' && content.charAt(i) != '\r') {
                    i++;
                }
                continue;
            }
            if (c == '(') {
                int start = i;
                i++;
                int depth = 1;
                while (i < len && depth > 0) {
                    char ch = content.charAt(i);
                    if (ch == '\\') {
                        i += 2;
                        continue;
                    }
                    if (ch == '(') depth++;
                    else if (ch == ')') depth--;
                    i++;
                }
                tokens.add(content.substring(start, Math.min(len, i)));
            } else if (c == '[') {
                int start = i;
                i++;
                int depth = 1;
                while (i < len && depth > 0) {
                    char ch = content.charAt(i);
                    if (ch == '(') {
                        i++;
                        int pDepth = 1;
                        while (i < len && pDepth > 0) {
                            char pc = content.charAt(i);
                            if (pc == '\\') {
                                i += 2;
                                continue;
                            }
                            if (pc == '(') pDepth++;
                            else if (pc == ')') pDepth--;
                            i++;
                        }
                        continue;
                    }
                    if (ch == '[') depth++;
                    else if (ch == ']') depth--;
                    i++;
                }
                tokens.add(content.substring(start, Math.min(len, i)));
            } else if (c == '<') {
                if (i + 1 < len && content.charAt(i + 1) == '<') {
                    tokens.add("<<");
                    i += 2;
                } else {
                    int start = i;
                    i++;
                    while (i < len && content.charAt(i) != '>') {
                        i++;
                    }
                    if (i < len) i++;
                    tokens.add(content.substring(start, i));
                }
            } else if (c == '>' && i + 1 < len && content.charAt(i + 1) == '>') {
                tokens.add(">>");
                i += 2;
            } else {
                int start = i;
                while (i < len) {
                    char ch = content.charAt(i);
                    if (Character.isWhitespace(ch) || ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == '<' || ch == '>') {
                        break;
                    }
                    i++;
                }
                tokens.add(content.substring(start, i));
            }
        }
        return tokens;
    }

    private static double[] multiplyMatrix(double[] m1, double[] m2) {
        return new double[]{
                m1[0] * m2[0] + m1[1] * m2[2],
                m1[0] * m2[1] + m1[1] * m2[3],
                m1[2] * m2[0] + m1[3] * m2[2],
                m1[2] * m2[1] + m1[3] * m2[3],
                m1[4] * m2[0] + m1[5] * m2[2] + m2[4],
                m1[4] * m2[1] + m1[5] * m2[3] + m2[5]
        };
    }

    private static int estimateCharWidthThousandths(char ch) {
        if (ch == ' ' || ch == ':' || ch == ';' || ch == '.' || ch == ',' || ch == '!' || ch == '|' || ch == 'i' || ch == 'l' || ch == 'I') {
            return 280;
        }
        if (ch == 'm' || ch == 'w' || ch == 'M' || ch == 'W' || ch == '@') {
            return 830;
        }
        if (Character.isUpperCase(ch)) {
            return 670;
        }
        return 550;
    }

    private static double parseDoubleSafe(String s, double fallback) {
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    // =========================================================================
    // PDF Object Tree, Page Resolution & Image Decoding
    // =========================================================================

    private static class PdfObject {
        int objNumber;
        int genNumber;
        String dictionary;
        boolean hasStream;
        boolean isFlateCompressed;
        boolean streamDecompressionFailed;
        byte[] rawStreamBytes;
        String streamContent;
    }

    private static class PdfParsedDocument {
        String header = "%PDF-1.4\n";
        List<PdfObject> objects = new ArrayList<>();
        Map<Integer, PdfObject> byNumber = new HashMap<>();
        String trailerDict = "<< /Size 1 >>";

        PdfObject getObjectByNumber(int num) {
            return byNumber.get(num);
        }
    }

    private record ResolvedPageNode(
            PdfObject pageObj,
            double widthPts,
            double heightPts,
            int rotationDegrees,
            String inheritedResources) {}

    private static byte[] readPdfBytes(Path sourcePath) throws DocumentProcessingException {
        try {
            return Files.readAllBytes(sourcePath);
        } catch (IOException e) {
            throw new DocumentProcessingException("Failed to read PDF bytes: " + sourcePath.getFileName(), e);
        }
    }

    private PdfParsedDocument parsePdf(byte[] data, String fileName) throws DocumentProcessingException {
        if (data == null || data.length < 16) {
            throw new DocumentProcessingException("Malformed or truncated PDF file: " + fileName);
        }
        PdfParsedDocument doc = new PdfParsedDocument();
        String fileContent = new String(data, StandardCharsets.ISO_8859_1);

        if (!fileContent.contains("%%EOF") && !fileContent.contains("endobj")) {
            throw new DocumentProcessingException(
                    "Malformed or truncated PDF file (missing %%EOF and object structure): " + fileName);
        }

        int firstLineEnd = fileContent.indexOf('\n');
        if (firstLineEnd > 0) {
            doc.header = fileContent.substring(0, firstLineEnd + 1);
        }

        int trailerIdx = fileContent.lastIndexOf("trailer");
        if (trailerIdx >= 0) {
            int trailerEnd = fileContent.indexOf("startxref", trailerIdx);
            if (trailerEnd > trailerIdx) {
                doc.trailerDict = fileContent.substring(trailerIdx + 7, trailerEnd).trim();
            }
        }

        Pattern objHeaderPattern = Pattern.compile("(?m)(?:^|\\s)(\\d+)\\s+(\\d+)\\s+obj\\b");
        Matcher objMatcher = objHeaderPattern.matcher(fileContent);

        int searchCursor = 0;
        while (objMatcher.find(searchCursor)) {
            int objNum = Integer.parseInt(objMatcher.group(1));
            int genNum = Integer.parseInt(objMatcher.group(2));
            int bodyStart = objMatcher.end();

            PdfObject obj = new PdfObject();
            obj.objNumber = objNum;
            obj.genNumber = genNum;

            // Check if a stream keyword follows the object dictionary before endobj
            int nextEndObjTentative = fileContent.indexOf("endobj", bodyStart);
            if (nextEndObjTentative < 0) {
                throw new DocumentProcessingException(
                        "Malformed PDF: unclosed object " + objNum + " in " + fileName);
            }

            int streamKeywordAbs = findStreamKeywordAfterDict(fileContent, bodyStart, nextEndObjTentative);
            int endObjIdx;

            if (streamKeywordAbs >= 0) {
                obj.hasStream = true;
                obj.dictionary = fileContent.substring(bodyStart, streamKeywordAbs).trim();

                int streamDataStartAbs = streamKeywordAbs + 6;
                if (streamDataStartAbs < fileContent.length() && fileContent.charAt(streamDataStartAbs) == '\r') {
                    streamDataStartAbs++;
                }
                if (streamDataStartAbs < fileContent.length() && fileContent.charAt(streamDataStartAbs) == '\n') {
                    streamDataStartAbs++;
                }

                int declaredLength = parseDirectLengthAttribute(obj.dictionary);
                int endStreamAbs = -1;
                int streamDataEndAbs = -1;

                if (declaredLength >= 0 && streamDataStartAbs + declaredLength <= data.length) {
                    int candidateEnd = streamDataStartAbs + declaredLength;
                    int esCheck = fileContent.indexOf("endstream", candidateEnd);
                    if (esCheck >= candidateEnd && esCheck <= candidateEnd + 4) {
                        streamDataEndAbs = candidateEnd;
                        endStreamAbs = esCheck;
                    }
                }

                if (endStreamAbs < 0) {
                    endStreamAbs = fileContent.indexOf("endstream", streamDataStartAbs);
                    if (endStreamAbs >= streamDataStartAbs) {
                        streamDataEndAbs = endStreamAbs;
                        if (streamDataEndAbs > streamDataStartAbs && fileContent.charAt(streamDataEndAbs - 1) == '\n') {
                            streamDataEndAbs--;
                            if (streamDataEndAbs > streamDataStartAbs && fileContent.charAt(streamDataEndAbs - 1) == '\r') {
                                streamDataEndAbs--;
                            }
                        }
                    }
                }

                if (endStreamAbs < streamDataStartAbs) {
                    obj.streamDecompressionFailed = true;
                    obj.rawStreamBytes = new byte[0];
                    endObjIdx = nextEndObjTentative;
                } else {
                    endObjIdx = fileContent.indexOf("endobj", endStreamAbs + 9);
                    if (endObjIdx < 0) {
                        throw new DocumentProcessingException(
                                "Malformed PDF: missing endobj after stream in object " + objNum);
                    }

                    byte[] streamBytes = new byte[Math.max(0, streamDataEndAbs - streamDataStartAbs)];
                    if (streamBytes.length > 0) {
                        System.arraycopy(data, streamDataStartAbs, streamBytes, 0, streamBytes.length);
                    }
                    obj.rawStreamBytes = streamBytes;

                    boolean isFlate = obj.dictionary != null && obj.dictionary.contains("/FlateDecode");
                    boolean isImage = obj.dictionary != null && obj.dictionary.contains("/Subtype")
                            && obj.dictionary.contains("/Image");

                    if (isFlate) {
                        obj.isFlateCompressed = true;
                        try {
                            byte[] decompressed = decompressFlate(streamBytes);
                            if (!isImage) {
                                obj.streamContent = new String(decompressed, StandardCharsets.ISO_8859_1);
                            }
                        } catch (IOException e) {
                            obj.streamDecompressionFailed = true;
                            obj.streamContent = "";
                        }
                    } else if (!isImage) {
                        obj.isFlateCompressed = false;
                        obj.streamContent = new String(streamBytes, StandardCharsets.ISO_8859_1);
                    }
                }
            } else {
                endObjIdx = nextEndObjTentative;
                obj.hasStream = false;
                obj.dictionary = fileContent.substring(bodyStart, endObjIdx).trim();
            }

            doc.objects.add(obj);
            doc.byNumber.put(obj.objNumber, obj);
            searchCursor = endObjIdx + 6;
        }

        if (doc.objects.isEmpty()) {
            throw new DocumentProcessingException("Malformed PDF: no objects found in " + fileName);
        }

        doc.objects.sort(Comparator.comparingInt(o -> o.objNumber));
        return doc;
    }

    private static int parseDirectLengthAttribute(String dict) {
        if (dict == null) return -1;
        // Match /Length N only when NOT followed by '0 R' (indirect object reference)
        Matcher m = Pattern.compile("/Length\\s+(\\d+)(?!\\s+\\d+\\s+R)").matcher(dict);
        if (m.find()) {
            return Integer.parseInt(m.group(1));
        }
        return -1;
    }

    private static int findStreamKeywordAfterDict(String fileContent, int bodyStart, int tentativeEndObj) {
        // Walk balanced << ... >> dictionary from bodyStart if present
        int i = bodyStart;
        while (i < tentativeEndObj && Character.isWhitespace(fileContent.charAt(i))) {
            i++;
        }
        if (i + 1 < tentativeEndObj && fileContent.charAt(i) == '<' && fileContent.charAt(i + 1) == '<') {
            int depth = 1;
            i += 2;
            while (i + 1 < fileContent.length() && depth > 0) {
                char c1 = fileContent.charAt(i);
                char c2 = fileContent.charAt(i + 1);
                if (c1 == '<' && c2 == '<') {
                    depth++;
                    i += 2;
                } else if (c1 == '>' && c2 == '>') {
                    depth--;
                    i += 2;
                } else {
                    i++;
                }
            }
            while (i < fileContent.length() && Character.isWhitespace(fileContent.charAt(i))) {
                i++;
            }
            if (fileContent.startsWith("stream\n", i) || fileContent.startsWith("stream\r\n", i)) {
                return i;
            }
        }
        return -1;
    }

    private static List<ResolvedPageNode> resolvePageTree(PdfParsedDocument doc) {
        List<ResolvedPageNode> resolved = new ArrayList<>();
        Set<Integer> visited = new HashSet<>();

        // Find root /Pages object via /Catalog if present
        PdfObject rootPages = null;
        for (PdfObject obj : doc.objects) {
            if (obj.dictionary != null && obj.dictionary.contains("/Type") && obj.dictionary.contains("/Catalog")) {
                Matcher m = Pattern.compile("/Pages\\s+(\\d+)\\s+\\d+\\s+R").matcher(obj.dictionary);
                if (m.find()) {
                    rootPages = doc.getObjectByNumber(Integer.parseInt(m.group(1)));
                    break;
                }
            }
        }

        if (rootPages != null) {
            traversePageTree(doc, rootPages, 612.0, 792.0, 0, "", visited, resolved);
        }

        // Fallback if any /Type /Page object was not linked via /Catalog
        if (resolved.isEmpty()) {
            for (PdfObject obj : doc.objects) {
                if (obj.dictionary != null && Pattern.compile("/Type\\s*/Page\\b").matcher(obj.dictionary).find()) {
                    double[] box = parseBoxDimensions(obj.dictionary, 612.0, 792.0);
                    int rot = parseRotation(obj.dictionary, 0);
                    resolved.add(new ResolvedPageNode(obj, box[0], box[1], rot, obj.dictionary));
                }
            }
        }
        return resolved;
    }

    private static void traversePageTree(
            PdfParsedDocument doc,
            PdfObject node,
            double inheritedW,
            double inheritedH,
            int inheritedRot,
            String inheritedRes,
            Set<Integer> visited,
            List<ResolvedPageNode> outPages) {
        if (node == null || !visited.add(node.objNumber) || node.dictionary == null) {
            return;
        }
        double[] box = parseBoxDimensions(node.dictionary, inheritedW, inheritedH);
        int rot = parseRotation(node.dictionary, inheritedRot);
        String res = node.dictionary.contains("/Resources") ? node.dictionary : inheritedRes;

        if (Pattern.compile("/Type\\s*/Pages\\b").matcher(node.dictionary).find()) {
            Matcher kidsMatcher = Pattern.compile("/Kids\\s*\\[([^\\]]*)\\]").matcher(node.dictionary);
            if (kidsMatcher.find()) {
                Matcher refMatcher = Pattern.compile("(\\d+)\\s+\\d+\\s+R").matcher(kidsMatcher.group(1));
                while (refMatcher.find()) {
                    PdfObject child = doc.getObjectByNumber(Integer.parseInt(refMatcher.group(1)));
                    traversePageTree(doc, child, box[0], box[1], rot, res, visited, outPages);
                }
            }
        } else if (Pattern.compile("/Type\\s*/Page\\b").matcher(node.dictionary).find()) {
            outPages.add(new ResolvedPageNode(node, box[0], box[1], rot, res));
        }
    }

    private static double[] parseBoxDimensions(String dict, double defaultW, double defaultH) {
        if (dict == null) return new double[]{defaultW, defaultH};
        Matcher crop = Pattern.compile("/CropBox\\s*\\[\\s*(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s*\\]").matcher(dict);
        if (crop.find()) {
            double w = Math.abs(Double.parseDouble(crop.group(3)) - Double.parseDouble(crop.group(1)));
            double h = Math.abs(Double.parseDouble(crop.group(4)) - Double.parseDouble(crop.group(2)));
            if (w > 1 && h > 1) return new double[]{w, h};
        }
        Matcher media = Pattern.compile("/MediaBox\\s*\\[\\s*(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s+(-?\\d+(?:\\.\\d+)?)\\s*\\]").matcher(dict);
        if (media.find()) {
            double w = Math.abs(Double.parseDouble(media.group(3)) - Double.parseDouble(media.group(1)));
            double h = Math.abs(Double.parseDouble(media.group(4)) - Double.parseDouble(media.group(2)));
            if (w > 1 && h > 1) return new double[]{w, h};
        }
        return new double[]{defaultW, defaultH};
    }

    private static int parseRotation(String dict, int defaultRot) {
        if (dict == null) return defaultRot;
        Matcher m = Pattern.compile("/Rotate\\s+(-?\\d+)").matcher(dict);
        if (m.find()) {
            return Integer.parseInt(m.group(1));
        }
        return defaultRot;
    }

    private static List<Integer> resolvePageContentStreamNumbers(PdfParsedDocument doc, PdfObject pageObj) {
        List<Integer> nums = new ArrayList<>();
        if (pageObj == null || pageObj.dictionary == null) return nums;

        Matcher arrMatcher = Pattern.compile("/Contents\\s*\\[([^\\]]*)\\]").matcher(pageObj.dictionary);
        if (arrMatcher.find()) {
            Matcher ref = Pattern.compile("(\\d+)\\s+\\d+\\s+R").matcher(arrMatcher.group(1));
            while (ref.find()) {
                nums.add(Integer.parseInt(ref.group(1)));
            }
            return nums;
        }

        Matcher singleMatcher = Pattern.compile("/Contents\\s+(\\d+)\\s+\\d+\\s+R").matcher(pageObj.dictionary);
        if (singleMatcher.find()) {
            int target = Integer.parseInt(singleMatcher.group(1));
            PdfObject targetObj = doc.getObjectByNumber(target);
            if (targetObj != null && !targetObj.hasStream && targetObj.dictionary != null && targetObj.dictionary.startsWith("[")) {
                Matcher ref = Pattern.compile("(\\d+)\\s+\\d+\\s+R").matcher(targetObj.dictionary);
                while (ref.find()) {
                    nums.add(Integer.parseInt(ref.group(1)));
                }
            } else {
                nums.add(target);
            }
        }
        return nums;
    }

    private static List<Integer> resolvePageImageObjectNumbers(
            PdfParsedDocument doc, PdfObject pageObj, String inheritedResources) {
        List<Integer> imgNums = new ArrayList<>();
        String combined = (pageObj.dictionary != null ? pageObj.dictionary : "") + " "
                + (inheritedResources != null ? inheritedResources : "");

        Matcher xObjBlock = Pattern.compile("/XObject\\s*<<([^>]*)>>").matcher(combined);
        while (xObjBlock.find()) {
            Matcher ref = Pattern.compile("/[A-Za-z0-9_]+\\s+(\\d+)\\s+\\d+\\s+R").matcher(xObjBlock.group(1));
            while (ref.find()) {
                int num = Integer.parseInt(ref.group(1));
                PdfObject candidate = doc.getObjectByNumber(num);
                if (candidate == null || (candidate.dictionary != null && candidate.dictionary.contains("/Image"))) {
                    if (!imgNums.contains(num)) {
                        imgNums.add(num);
                    }
                }
            }
        }
        return imgNums;
    }

    private static String findXObjectNameForObjNum(String dictText, int objNum) {
        Matcher m = Pattern.compile("(/[A-Za-z0-9_]+)\\s+" + objNum + "\\s+\\d+\\s+R").matcher(dictText);
        if (m.find()) {
            return m.group(1);
        }
        return "/Im1";
    }

    private static BufferedImage decodePdfImageObject(PdfObject imgObj) {
        if (imgObj == null || imgObj.rawStreamBytes == null || imgObj.rawStreamBytes.length == 0) {
            return null;
        }
        String dict = imgObj.dictionary != null ? imgObj.dictionary : "";
        byte[] streamBytes = imgObj.rawStreamBytes;

        // 1. Try standard ImageIO (handles /DCTDecode JPEG, PNG streams, etc.)
        try {
            BufferedImage direct = ImageIO.read(new ByteArrayInputStream(streamBytes));
            if (direct != null && direct.getWidth() > 0 && direct.getHeight() > 0) {
                return direct;
            }
        } catch (IOException ignored) {
        }

        // 2. Decompress /FlateDecode if compressed
        byte[] pixelBytes = streamBytes;
        if (imgObj.isFlateCompressed || dict.contains("/FlateDecode")) {
            try {
                pixelBytes = decompressFlate(streamBytes);
            } catch (IOException e) {
                return null;
            }
            // Check if decompressed bytes are a PNG/BMP image
            try {
                BufferedImage decompImg = ImageIO.read(new ByteArrayInputStream(pixelBytes));
                if (decompImg != null && decompImg.getWidth() > 0 && decompImg.getHeight() > 0) {
                    return decompImg;
                }
            } catch (IOException ignored) {
            }
        }

        // 3. Decode raw /DeviceRGB or /DeviceGray pixel buffer using /Width and /Height
        int w = parseIntAttribute(dict, "/Width", -1);
        int h = parseIntAttribute(dict, "/Height", -1);
        int bpc = parseIntAttribute(dict, "/BitsPerComponent", 8);
        if (w <= 0 || h <= 0) {
            return null;
        }

        boolean isGray = dict.contains("/DeviceGray");
        if (isGray && bpc == 8 && pixelBytes.length >= w * h) {
            BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
            int idx = 0;
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) {
                    int v = pixelBytes[idx++] & 0xFF;
                    int rgb = (v << 16) | (v << 8) | v;
                    img.setRGB(x, y, rgb);
                }
            }
            return img;
        } else if (!isGray && bpc == 8 && pixelBytes.length >= w * h * 3) {
            BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
            int idx = 0;
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) {
                    int r = pixelBytes[idx++] & 0xFF;
                    int g = pixelBytes[idx++] & 0xFF;
                    int b = pixelBytes[idx++] & 0xFF;
                    img.setRGB(x, y, (r << 16) | (g << 8) | b);
                }
            }
            return img;
        }
        return null;
    }

    private static int parseIntAttribute(String dict, String key, int defaultValue) {
        Matcher m = Pattern.compile(Pattern.quote(key) + "\\s+(\\d+)").matcher(dict);
        if (m.find()) {
            return Integer.parseInt(m.group(1));
        }
        return defaultValue;
    }

    private static void updatePdfStreamObject(PdfObject obj, byte[] uncompressedBytes, boolean compress) {
        obj.streamContent = new String(uncompressedBytes, StandardCharsets.ISO_8859_1);
        if (compress) {
            obj.isFlateCompressed = true;
            obj.rawStreamBytes = compressFlate(uncompressedBytes);
        } else {
            obj.isFlateCompressed = false;
            obj.rawStreamBytes = uncompressedBytes;
        }
        if (obj.dictionary != null) {
            if (obj.dictionary.matches("(?s).*/Length\\s+\\d+.*")) {
                obj.dictionary = obj.dictionary.replaceAll("/Length\\s+\\d+", "/Length " + obj.rawStreamBytes.length);
            } else {
                obj.dictionary = obj.dictionary.replace(">>", " /Length " + obj.rawStreamBytes.length + " >>");
            }
        }
    }

    private static byte[] decompressFlate(byte[] compressed) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
             InflaterInputStream iis = new InflaterInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int read;
            while ((read = iis.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
            return baos.toByteArray();
        }
    }

    public static byte[] compressFlate(byte[] uncompressed) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DeflaterOutputStream dos = new DeflaterOutputStream(baos)) {
            dos.write(uncompressed);
            dos.finish();
            return baos.toByteArray();
        } catch (IOException e) {
            return uncompressed;
        }
    }

    private static String decodePdfStringOrHexToken(String token) {
        if (token == null || token.length() < 2) return "";
        if (token.startsWith("(") && token.endsWith(")")) {
            return unescapePdfString(token.substring(1, token.length() - 1));
        }
        if (token.startsWith("<") && token.endsWith(">")) {
            String hex = token.substring(1, token.length() - 1).replaceAll("\\s+", "");
            if (hex.length() % 2 != 0) hex = hex + "0";
            byte[] bytes = new byte[hex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                try {
                    bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                } catch (NumberFormatException ignored) {
                }
            }
            if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xFF) == 0xFF) {
                return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16BE);
            }
            return new String(bytes, StandardCharsets.ISO_8859_1);
        }
        return token;
    }

    private static String decodeTjArrayText(String arrayBody) {
        Pattern p = Pattern.compile("(\\((?:\\\\.|[^\\\\()])*\\)|<[0-9A-Fa-f\\s]*>)");
        Matcher m = p.matcher(arrayBody);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            sb.append(decodePdfStringOrHexToken(m.group(1)));
        }
        return sb.toString();
    }

    private static String unescapePdfString(String pdfStr) {
        if (pdfStr == null || pdfStr.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(pdfStr.length());
        int len = pdfStr.length();
        for (int i = 0; i < len; i++) {
            char c = pdfStr.charAt(i);
            if (c == '\\' && i + 1 < len) {
                char next = pdfStr.charAt(++i);
                switch (next) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case '(' -> sb.append('(');
                    case ')' -> sb.append(')');
                    case '\\' -> sb.append('\\');
                    default -> {
                        if (next >= '0' && next <= '7') {
                            StringBuilder oct = new StringBuilder();
                            oct.append(next);
                            while (i + 1 < len && oct.length() < 3
                                    && pdfStr.charAt(i + 1) >= '0' && pdfStr.charAt(i + 1) <= '7') {
                                oct.append(pdfStr.charAt(++i));
                            }
                            sb.append((char) Integer.parseInt(oct.toString(), 8));
                        } else {
                            sb.append(next);
                        }
                    }
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String escapePdfString(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        return raw.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    private static byte[] assemblePdf(PdfParsedDocument doc) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            String header = doc.header.endsWith("\n") ? doc.header : doc.header + "\n";
            baos.write(header.getBytes(StandardCharsets.US_ASCII));

            Map<Integer, Long> objectOffsets = new HashMap<>();
            int maxObjNum = 0;
            for (PdfObject obj : doc.objects) {
                if (obj.objNumber > maxObjNum) {
                    maxObjNum = obj.objNumber;
                }
            }

            for (PdfObject obj : doc.objects) {
                long offset = baos.size();
                objectOffsets.put(obj.objNumber, offset);

                String objHeader = obj.objNumber + " " + obj.genNumber + " obj\n";
                baos.write(objHeader.getBytes(StandardCharsets.US_ASCII));

                if (obj.dictionary != null && !obj.dictionary.isEmpty()) {
                    baos.write(obj.dictionary.getBytes(StandardCharsets.ISO_8859_1));
                    baos.write("\n".getBytes(StandardCharsets.US_ASCII));
                }

                if (obj.hasStream) {
                    baos.write("stream\n".getBytes(StandardCharsets.US_ASCII));
                    if (obj.rawStreamBytes != null && obj.rawStreamBytes.length > 0) {
                        baos.write(obj.rawStreamBytes);
                    }
                    baos.write("\nendstream\n".getBytes(StandardCharsets.US_ASCII));
                }

                baos.write("endobj\n".getBytes(StandardCharsets.US_ASCII));
            }

            long xrefOffset = baos.size();
            baos.write("xref\n".getBytes(StandardCharsets.US_ASCII));
            int totalCount = maxObjNum + 1;
            baos.write(("0 " + totalCount + "\n").getBytes(StandardCharsets.US_ASCII));
            baos.write("0000000000 65535 f \n".getBytes(StandardCharsets.US_ASCII));

            for (int i = 1; i <= maxObjNum; i++) {
                Long offset = objectOffsets.get(i);
                if (offset != null) {
                    baos.write(String.format(Locale.ROOT, "%010d 00000 n \n", offset).getBytes(StandardCharsets.US_ASCII));
                } else {
                    baos.write("0000000000 00000 f \n".getBytes(StandardCharsets.US_ASCII));
                }
            }

            baos.write("trailer\n".getBytes(StandardCharsets.US_ASCII));
            String trailer = doc.trailerDict;
            if (!trailer.contains("/Size")) {
                trailer = trailer.replace("<<", "<< /Size " + totalCount + " ");
            } else {
                trailer = trailer.replaceAll("/Size\\s+\\d+", "/Size " + totalCount);
            }
            baos.write(trailer.getBytes(StandardCharsets.ISO_8859_1));
            baos.write("\n".getBytes(StandardCharsets.US_ASCII));

            baos.write("startxref\n".getBytes(StandardCharsets.US_ASCII));
            baos.write((xrefOffset + "\n").getBytes(StandardCharsets.US_ASCII));
            baos.write("%%EOF\n".getBytes(StandardCharsets.US_ASCII));
        } catch (IOException ignored) {
        }
        return baos.toByteArray();
    }

    /**
     * Renders or extracts the visual page image of a saved PDF page (1-based) for inspection and testing.
     */
    public BufferedImage renderPageImage(Path pdfPath, int pageNumber) throws DocumentProcessingException {
        validatePdfHeader(pdfPath);
        byte[] raw = readPdfBytes(pdfPath);
        PdfParsedDocument doc = parsePdf(raw, pdfPath.getFileName().toString());
        ExtractedDocumentData data = extractDocumentPages(doc, pdfPath, false);
        if (pageNumber < 1 || pageNumber > data.pages.size()) {
            throw new DocumentProcessingException("Page " + pageNumber + " out of bounds");
        }
        ExtractedPageData p = data.pages.get(pageNumber - 1);
        if (!p.images.isEmpty()) {
            return p.images.get(0).image;
        }
        int w = (int) Math.round(p.widthPts);
        int h = (int) Math.round(p.heightPts);
        BufferedImage canvas = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = canvas.createGraphics();
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, w, h);
        g2.setColor(Color.BLACK);
        g2.setFont(new Font("SansSerif", Font.PLAIN, 12));
        for (CharOrigin co : p.charOrigins) {
            if (co != null && co.boundingBox != null && co.ch != '\n') {
                int px = (int) Math.round(co.boundingBox.getX());
                int py = (int) Math.round(co.boundingBox.getTopDownY() + co.boundingBox.getHeight());
                g2.drawString(String.valueOf(co.ch), px, py);
            }
        }
        g2.dispose();
        return canvas;
    }
}
