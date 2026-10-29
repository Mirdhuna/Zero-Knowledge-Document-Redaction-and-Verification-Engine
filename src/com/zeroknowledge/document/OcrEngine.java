package com.zeroknowledge.document;

import com.zeroknowledge.model.PdfBoundingBox;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Abstraction for local Optical Character Recognition (OCR) on scanned PDF page images.
 * Strictly local — never uploads confidential documents to external services.
 */
public interface OcrEngine {

    /**
     * Describes whether the local OCR engine executable and language data are available.
     */
    final class OcrAvailability {
        private final boolean available;
        private final String executablePath;
        private final String versionInfo;
        private final String configuredLanguage;
        private final boolean languageAvailable;
        private final String statusMessage;
        private final String setupInstructions;

        public OcrAvailability(
                boolean available,
                String executablePath,
                String versionInfo,
                String configuredLanguage,
                boolean languageAvailable,
                String statusMessage,
                String setupInstructions) {
            this.available = available;
            this.executablePath = executablePath == null ? "" : executablePath;
            this.versionInfo = versionInfo == null ? "" : versionInfo;
            this.configuredLanguage = configuredLanguage == null ? "eng" : configuredLanguage;
            this.languageAvailable = languageAvailable;
            this.statusMessage = Objects.requireNonNull(statusMessage, "statusMessage must not be null");
            this.setupInstructions = setupInstructions == null ? "" : setupInstructions;
        }

        public boolean isAvailable() {
            return available;
        }

        public String getExecutablePath() {
            return executablePath;
        }

        public String getVersionInfo() {
            return versionInfo;
        }

        public String getConfiguredLanguage() {
            return configuredLanguage;
        }

        public boolean isLanguageAvailable() {
            return languageAvailable;
        }

        public String getStatusMessage() {
            return statusMessage;
        }

        public String getSetupInstructions() {
            return setupInstructions;
        }
    }

    /**
     * Represents a single word recognized by OCR along with its character offset span,
     * confidence, original image pixel coordinates, and mapped PDF page bounding box.
     */
    final class OcrWordBox {
        private final String text;
        private final double confidence;
        private final int startCharOffset;
        private final int endCharOffset;
        private final int lineId;
        private final Rectangle imagePixelRect;
        private final PdfBoundingBox pdfBoundingBox;

        public OcrWordBox(
                String text,
                double confidence,
                int startCharOffset,
                int endCharOffset,
                int lineId,
                Rectangle imagePixelRect,
                PdfBoundingBox pdfBoundingBox) {
            this.text = Objects.requireNonNull(text, "text must not be null");
            this.confidence = Math.max(0.0, Math.min(1.0, confidence));
            this.startCharOffset = startCharOffset;
            this.endCharOffset = endCharOffset;
            this.lineId = lineId;
            this.imagePixelRect = Objects.requireNonNull(imagePixelRect, "imagePixelRect must not be null");
            this.pdfBoundingBox = Objects.requireNonNull(pdfBoundingBox, "pdfBoundingBox must not be null");
        }

        public String getText() {
            return text;
        }

        public double getConfidence() {
            return confidence;
        }

        public int getStartCharOffset() {
            return startCharOffset;
        }

        public int getEndCharOffset() {
            return endCharOffset;
        }

        public int getLineId() {
            return lineId;
        }

        public Rectangle getImagePixelRect() {
            return new Rectangle(imagePixelRect);
        }

        public PdfBoundingBox getPdfBoundingBox() {
            return pdfBoundingBox;
        }
    }

    /**
     * Result of running OCR on a single scanned image or rendered PDF page.
     */
    final class OcrExtractionResult {
        private final boolean success;
        private final boolean ocrUnavailable;
        private final String extractedText;
        private final double averageConfidence;
        private final List<OcrWordBox> wordBoxes;
        private final String diagnosticMessage;

        public OcrExtractionResult(
                boolean success,
                boolean ocrUnavailable,
                String extractedText,
                double averageConfidence,
                List<OcrWordBox> wordBoxes,
                String diagnosticMessage) {
            this.success = success;
            this.ocrUnavailable = ocrUnavailable;
            this.extractedText = extractedText == null ? "" : extractedText;
            this.averageConfidence = averageConfidence;
            this.wordBoxes = wordBoxes == null
                    ? List.of()
                    : Collections.unmodifiableList(List.copyOf(wordBoxes));
            this.diagnosticMessage = diagnosticMessage == null ? "" : diagnosticMessage;
        }

        public static OcrExtractionResult unavailable(String message) {
            return new OcrExtractionResult(false, true, "", -1.0, List.of(), message);
        }

        public static OcrExtractionResult failed(String message) {
            return new OcrExtractionResult(false, false, "", -1.0, List.of(), message);
        }

        public boolean isSuccess() {
            return success;
        }

        public boolean isOcrUnavailable() {
            return ocrUnavailable;
        }

        public String getExtractedText() {
            return extractedText;
        }

        public double getAverageConfidence() {
            return averageConfidence;
        }

        public List<OcrWordBox> getWordBoxes() {
            return wordBoxes;
        }

        public String getDiagnosticMessage() {
            return diagnosticMessage;
        }

        /**
         * Maps a character offset span {@code [startOffset, endOffset)} in {@link #getExtractedText()}
         * to one or more tight {@link PdfBoundingBox} regions on the PDF page.
         *
         * <p>If a match spans only part of a word token (e.g., value after a colon), proportionally
         * slices the word's horizontal bounding box; if it spans multiple words on the same line,
         * combines adjacent boxes on that line without covering unrelated lines.
         */
        public List<PdfBoundingBox> mapSpanToBoundingBoxes(int startOffset, int endOffset) {
            if (wordBoxes.isEmpty() || endOffset <= startOffset) {
                return List.of();
            }

            List<PdfBoundingBox> rawBoxes = new ArrayList<>();
            for (OcrWordBox wb : wordBoxes) {
                if (wb.getEndCharOffset() <= startOffset || wb.getStartCharOffset() >= endOffset) {
                    continue;
                }
                PdfBoundingBox fullBox = wb.getPdfBoundingBox();
                int wordLen = Math.max(1, wb.getEndCharOffset() - wb.getStartCharOffset());
                int subStart = Math.max(0, startOffset - wb.getStartCharOffset());
                int subEnd = Math.min(wordLen, endOffset - wb.getStartCharOffset());

                if (subStart == 0 && subEnd == wordLen) {
                    rawBoxes.add(fullBox);
                } else {
                    double fracStart = (double) subStart / wordLen;
                    double fracWidth = (double) Math.max(1, subEnd - subStart) / wordLen;
                    double slicedX = fullBox.getX() + fullBox.getWidth() * fracStart;
                    double slicedW = Math.max(2.0, fullBox.getWidth() * fracWidth);
                    rawBoxes.add(new PdfBoundingBox(
                            fullBox.getPageNumber(),
                            slicedX,
                            fullBox.getY(),
                            slicedW,
                            fullBox.getHeight(),
                            fullBox.getPageWidth(),
                            fullBox.getPageHeight(),
                            fullBox.getRotation()));
                }
            }

            if (rawBoxes.isEmpty()) {
                return List.of();
            }

            // Merge adjacent boxes on the same line while keeping different lines separate
            List<PdfBoundingBox> merged = new ArrayList<>();
            PdfBoundingBox current = rawBoxes.get(0);
            for (int i = 1; i < rawBoxes.size(); i++) {
                PdfBoundingBox next = rawBoxes.get(i);
                double maxGap = Math.max(18.0, current.getHeight() * 1.8);
                if (current.canMergeOnSameLine(next, maxGap)) {
                    current = current.union(next);
                } else {
                    merged.add(current);
                    current = next;
                }
            }
            merged.add(current);
            return Collections.unmodifiableList(merged);
        }

        /**
         * Computes the minimum word confidence among all OCR words overlapping {@code [startOffset, endOffset)}.
         */
        public double getConfidenceForSpan(int startOffset, int endOffset) {
            double minConf = 1.0;
            boolean found = false;
            for (OcrWordBox wb : wordBoxes) {
                if (wb.getEndCharOffset() > startOffset && wb.getStartCharOffset() < endOffset) {
                    minConf = Math.min(minConf, wb.getConfidence());
                    found = true;
                }
            }
            return found ? minConf : (averageConfidence >= 0 ? averageConfidence : 0.0);
        }
    }

    /**
     * Checks whether the OCR engine and configured language pack are available locally.
     */
    OcrAvailability checkAvailability();

    /**
     * Performs preprocessing and OCR on the given image, mapping recognized word coordinates
     * to the target PDF page.
     *
     * @param image                raw page or XObject image
     * @param pageNumber           1-based PDF page number
     * @param imagePlacementOnPage placement box of the image on the PDF page in points
     * @param fullPageWidthPts     full PDF page width in points
     * @param fullPageHeightPts    full PDF page height in points
     * @param pageRotation         page rotation in degrees (0, 90, 180, 270)
     * @return structured {@link OcrExtractionResult}
     */
    OcrExtractionResult recognizeImage(
            BufferedImage image,
            int pageNumber,
            PdfBoundingBox imagePlacementOnPage,
            double fullPageWidthPts,
            double fullPageHeightPts,
            int pageRotation);
}
