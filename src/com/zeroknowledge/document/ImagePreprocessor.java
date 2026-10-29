package com.zeroknowledge.document;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.util.Arrays;
import java.util.Objects;

/**
 * Image preprocessing pipeline for scanned PDF pages prior to OCR.
 *
 * <h3>Capabilities</h3>
 * <ul>
 *   <li><strong>Resolution Scaling</strong>: Bicubic upscaling for low-resolution page rasters.</li>
 *   <li><strong>Grayscale Conversion</strong>: ITU-R BT.601 luminance extraction.</li>
 *   <li><strong>Contrast Enhancement</strong>: Dynamic histogram percentile stretching for low-contrast scans.</li>
 *   <li><strong>Noise Reduction</strong>: 3x3 impulse-noise despeckle median filter preserving glyph strokes.</li>
 *   <li><strong>Deskewing</strong>: Horizontal projection-profile variance maximization to correct page tilt.</li>
 *   <li><strong>Adaptive/Otsu Binarization</strong>: Thresholding to crisp black-on-white text for OCR.</li>
 *   <li><strong>Reversible Coordinate Mapping</strong>: Maps OCR bounding boxes from preprocessed pixel coordinates
 *       back to exact original image pixel coordinates.</li>
 * </ul>
 */
public final class ImagePreprocessor {

    /**
     * Holds the preprocessed image along with transformation parameters needed to map
     * OCR bounding boxes back to the original image's coordinate system.
     */
    public static final class PreprocessedImage {
        private final BufferedImage image;
        private final int originalWidth;
        private final int originalHeight;
        private final double scaleFactor;
        private final double appliedDeskewDegrees;
        private final boolean contrastEnhanced;

        public PreprocessedImage(
                BufferedImage image,
                int originalWidth,
                int originalHeight,
                double scaleFactor,
                double appliedDeskewDegrees,
                boolean contrastEnhanced) {
            this.image = Objects.requireNonNull(image, "image must not be null");
            this.originalWidth = originalWidth;
            this.originalHeight = originalHeight;
            this.scaleFactor = scaleFactor > 0 ? scaleFactor : 1.0;
            this.appliedDeskewDegrees = appliedDeskewDegrees;
            this.contrastEnhanced = contrastEnhanced;
        }

        public BufferedImage getImage() {
            return image;
        }

        public int getOriginalWidth() {
            return originalWidth;
        }

        public int getOriginalHeight() {
            return originalHeight;
        }

        public double getScaleFactor() {
            return scaleFactor;
        }

        public double getAppliedDeskewDegrees() {
            return appliedDeskewDegrees;
        }

        public boolean isContrastEnhanced() {
            return contrastEnhanced;
        }

        /**
         * Maps a bounding box from preprocessed image pixel coordinates back to the original
         * image pixel coordinates, reversing deskew rotation and upscaling.
         */
        public Rectangle mapToOriginalPixels(int prepLeft, int prepTop, int prepWidth, int prepHeight) {
            double x1 = prepLeft;
            double y1 = prepTop;
            double x2 = prepLeft + prepWidth;
            double y2 = prepTop + prepHeight;

            if (Math.abs(appliedDeskewDegrees) >= 0.05) {
                double cx = image.getWidth() / 2.0;
                double cy = image.getHeight() / 2.0;
                // Reverse the deskew rotation (-appliedDeskewDegrees)
                double rad = Math.toRadians(-appliedDeskewDegrees);
                double cos = Math.cos(rad);
                double sin = Math.sin(rad);

                double[][] corners = {
                        {x1, y1}, {x2, y1}, {x2, y2}, {x1, y2}
                };
                double minX = Double.POSITIVE_INFINITY;
                double minY = Double.POSITIVE_INFINITY;
                double maxX = Double.NEGATIVE_INFINITY;
                double maxY = Double.NEGATIVE_INFINITY;

                for (double[] pt : corners) {
                    double dx = pt[0] - cx;
                    double dy = pt[1] - cy;
                    double rx = cx + dx * cos - dy * sin;
                    double ry = cy + dx * sin + dy * cos;
                    minX = Math.min(minX, rx);
                    minY = Math.min(minY, ry);
                    maxX = Math.max(maxX, rx);
                    maxY = Math.max(maxY, ry);
                }
                x1 = minX;
                y1 = minY;
                x2 = maxX;
                y2 = maxY;
            }

            int origLeft = (int) Math.floor(x1 / scaleFactor);
            int origTop = (int) Math.floor(y1 / scaleFactor);
            int origRight = (int) Math.ceil(x2 / scaleFactor);
            int origBottom = (int) Math.ceil(y2 / scaleFactor);

            int clampedLeft = Math.max(0, Math.min(originalWidth - 1, origLeft));
            int clampedTop = Math.max(0, Math.min(originalHeight - 1, origTop));
            int clampedRight = Math.max(clampedLeft + 1, Math.min(originalWidth, origRight));
            int clampedBottom = Math.max(clampedTop + 1, Math.min(originalHeight, origBottom));

            return new Rectangle(
                    clampedLeft,
                    clampedTop,
                    clampedRight - clampedLeft,
                    clampedBottom - clampedTop);
        }
    }

    private ImagePreprocessor() {}

    /**
     * Executes the full preprocessing pipeline on a source page or embedded image.
     */
    public static PreprocessedImage preprocess(BufferedImage source, int targetDpi) {
        Objects.requireNonNull(source, "source image must not be null");
        int origW = source.getWidth();
        int origH = source.getHeight();

        // 1. Resolution upscaling if image is small (< 900px on both dimensions)
        double scale = 1.0;
        BufferedImage working = source;
        if (origW < 900 && origH < 900 && origW * origH < 600_000) {
            scale = 2.0;
            int scaledW = Math.max(1, (int) Math.round(origW * scale));
            int scaledH = Math.max(1, (int) Math.round(origH * scale));
            BufferedImage upscaled = new BufferedImage(scaledW, scaledH, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2 = upscaled.createGraphics();
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g2.drawImage(source, 0, 0, scaledW, scaledH, null);
            g2.dispose();
            working = upscaled;
        }

        int w = working.getWidth();
        int h = working.getHeight();

        // 2. Grayscale conversion
        int[] gray = toGrayscaleArray(working);

        // 3. Contrast enhancement via percentile histogram stretching
        boolean contrastStretched = enhanceContrastInPlace(gray);

        // 4. Impulse noise reduction (3x3 edge-preserving despeckle)
        int[] denoised = reduceImpulseNoise(gray, w, h);

        // 5. Compute Otsu threshold and binarize
        int threshold = computeOtsuThreshold(denoised);
        BufferedImage binaryImg = createBinaryImage(denoised, w, h, threshold);

        // 6. Estimate skew angle and deskew if tilted
        double skewDeg = estimateSkewDegrees(denoised, w, h, threshold);
        double appliedDeskew = 0.0;
        if (Math.abs(skewDeg) >= 0.4 && Math.abs(skewDeg) <= 12.0) {
            appliedDeskew = -skewDeg;
            binaryImg = rotateImageWhiteBg(binaryImg, appliedDeskew);
        }

        return new PreprocessedImage(binaryImg, origW, origH, scale, appliedDeskew, contrastStretched);
    }

    private static int[] toGrayscaleArray(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        int[] rgb = img.getRGB(0, 0, w, h, null, 0, w);
        int[] gray = new int[rgb.length];
        for (int i = 0; i < rgb.length; i++) {
            int p = rgb[i];
            int r = (p >> 16) & 0xFF;
            int g = (p >> 8) & 0xFF;
            int b = p & 0xFF;
            gray[i] = (77 * r + 150 * g + 29 * b) >> 8;
        }
        return gray;
    }

    private static boolean enhanceContrastInPlace(int[] gray) {
        if (gray.length == 0) {
            return false;
        }
        int[] hist = new int[256];
        int minVal = 255;
        int maxVal = 0;
        for (int v : gray) {
            hist[v]++;
            if (v < minVal) minVal = v;
            if (v > maxVal) maxVal = v;
        }
        if (maxVal <= minVal) {
            return false;
        }

        int total = gray.length;
        int lowCut = Math.max(1, (int) (total * 0.005));
        int highCut = Math.max(1, (int) (total * 0.995));

        int pLow = minVal;
        int sum = 0;
        for (int i = 0; i < 256; i++) {
            sum += hist[i];
            if (sum >= lowCut) {
                pLow = i;
                break;
            }
        }

        int pHigh = maxVal;
        sum = 0;
        for (int i = 0; i < 256; i++) {
            sum += hist[i];
            if (sum >= highCut) {
                pHigh = i;
                break;
            }
        }

        if (pHigh <= pLow) {
            pLow = minVal;
            pHigh = maxVal;
        }

        int range = pHigh - pLow;
        if (range <= 0 || range >= 235) {
            return false;
        }

        for (int i = 0; i < gray.length; i++) {
            int stretched = ((gray[i] - pLow) * 255) / range;
            gray[i] = Math.max(0, Math.min(255, stretched));
        }
        return true;
    }

    private static int[] reduceImpulseNoise(int[] gray, int w, int h) {
        if (w < 3 || h < 3) {
            return gray;
        }
        int[] out = Arrays.copyOf(gray, gray.length);
        int[] window = new int[9];
        for (int y = 1; y < h - 1; y++) {
            int rowOffset = y * w;
            for (int x = 1; x < w - 1; x++) {
                int center = gray[rowOffset + x];
                // Only filter isolated extreme impulse spikes to preserve sharp glyph corners
                int diffCount = 0;
                int k = 0;
                for (int dy = -1; dy <= 1; dy++) {
                    int rOff = (y + dy) * w;
                    for (int dx = -1; dx <= 1; dx++) {
                        int neighbor = gray[rOff + x + dx];
                        window[k++] = neighbor;
                        if (Math.abs(neighbor - center) > 95) {
                            diffCount++;
                        }
                    }
                }
                if (diffCount >= 7) {
                    Arrays.sort(window);
                    out[rowOffset + x] = window[4];
                }
            }
        }
        return out;
    }

    public static int computeOtsuThreshold(int[] gray) {
        int[] hist = new int[256];
        int minVal = 255;
        int maxVal = 0;
        for (int v : gray) {
            hist[v]++;
            if (v < minVal) minVal = v;
            if (v > maxVal) maxVal = v;
        }
        if (minVal == maxVal) {
            return 128;
        }

        int total = gray.length;
        double sum = 0;
        for (int i = 0; i < 256; i++) {
            sum += (double) i * hist[i];
        }

        double sumB = 0;
        int wB = 0;
        double maxVariance = -1.0;
        int bestThreshold = (minVal + maxVal) / 2;

        for (int t = 0; t < 256; t++) {
            wB += hist[t];
            if (wB == 0) continue;
            int wF = total - wB;
            if (wF == 0) break;

            sumB += (double) t * hist[t];
            double mB = sumB / wB;
            double mF = (sum - sumB) / wF;
            double diff = mB - mF;
            double betweenVar = (double) wB * (double) wF * diff * diff;
            if (betweenVar > maxVariance) {
                maxVariance = betweenVar;
                bestThreshold = t;
            }
        }
        return Math.max(10, Math.min(245, bestThreshold));
    }

    private static BufferedImage createBinaryImage(int[] gray, int w, int h, int threshold) {
        BufferedImage out = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        int[] rgb = new int[gray.length];
        for (int i = 0; i < gray.length; i++) {
            rgb[i] = (gray[i] <= threshold) ? 0x000000 : 0xFFFFFF;
        }
        out.setRGB(0, 0, w, h, rgb, 0, w);
        return out;
    }

    private static double estimateSkewDegrees(int[] gray, int w, int h, int threshold) {
        // Sample dark pixels to evaluate horizontal projection variance across small angles
        int step = Math.max(1, Math.min(w, h) / 300);
        int darkCount = 0;
        for (int y = 0; y < h; y += step) {
            int off = y * w;
            for (int x = 0; x < w; x += step) {
                if (gray[off + x] <= threshold) {
                    darkCount++;
                }
            }
        }
        if (darkCount < 30) {
            return 0.0;
        }

        double bestAngle = 0.0;
        double maxVariance = -1.0;
        double cx = w / 2.0;
        double cy = h / 2.0;

        for (double deg = -5.0; deg <= 5.0; deg += 0.5) {
            double var = computeProjectionVariance(gray, w, h, threshold, step, cx, cy, deg);
            if (var > maxVariance) {
                maxVariance = var;
                bestAngle = deg;
            }
        }

        // Check if 0.0 is already within 2% of max variance to avoid unnecessary rotation on straight pages
        double zeroVar = computeProjectionVariance(gray, w, h, threshold, step, cx, cy, 0.0);
        if (zeroVar >= maxVariance * 0.96) {
            return 0.0;
        }
        return bestAngle;
    }

    private static double computeProjectionVariance(
            int[] gray, int w, int h, int threshold, int step, double cx, double cy, double deg) {
        double rad = Math.toRadians(-deg);
        double sin = Math.sin(rad);
        double cos = Math.cos(rad);
        int[] rowCounts = new int[h];

        for (int y = 0; y < h; y += step) {
            int off = y * w;
            double dy = y - cy;
            for (int x = 0; x < w; x += step) {
                if (gray[off + x] <= threshold) {
                    int projY = (int) Math.round(cy + (x - cx) * sin + dy * cos);
                    if (projY >= 0 && projY < h) {
                        rowCounts[projY]++;
                    }
                }
            }
        }

        double sum = 0;
        double sumSq = 0;
        for (int c : rowCounts) {
            sum += c;
            sumSq += (double) c * c;
        }
        double mean = sum / h;
        return (sumSq / h) - (mean * mean);
    }

    private static BufferedImage rotateImageWhiteBg(BufferedImage src, double angleDegrees) {
        int w = src.getWidth();
        int h = src.getHeight();
        BufferedImage dst = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = dst.createGraphics();
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, w, h);
        g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        AffineTransform at = new AffineTransform();
        at.rotate(Math.toRadians(angleDegrees), w / 2.0, h / 2.0);
        g2.drawRenderedImage(src, at);
        g2.dispose();
        return dst;
    }
}
