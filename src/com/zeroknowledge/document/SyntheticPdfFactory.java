package com.zeroknowledge.document;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Deflater;

/**
 * Generates synthetic PDF 1.4 documents and rasterized page images containing
 * strictly fake test data for automated verification of Stage 1–Stage 8.
 */
public final class SyntheticPdfFactory {

    private SyntheticPdfFactory() {
    }

    /**
     * Represents a single synthetic page specification (native text stream, embedded image, or both).
     */
    public static final class SyntheticPageSpec {
        private final String nativeContentStream;
        private final BufferedImage embeddedImage;
        private final int rotationDegrees;
        private final boolean compressStream;

        public SyntheticPageSpec(
                String nativeContentStream,
                BufferedImage embeddedImage,
                int rotationDegrees,
                boolean compressStream) {
            this.nativeContentStream = nativeContentStream;
            this.embeddedImage = embeddedImage;
            this.rotationDegrees = rotationDegrees;
            this.compressStream = compressStream;
        }

        public static SyntheticPageSpec nativeTextPage(List<String> lines, int rotationDegrees, boolean compress) {
            StringBuilder sb = new StringBuilder();
            sb.append("BT\n/F1 11 Tf\n18 TL\n1 0 0 1 54 720 Tm\n");
            for (int i = 0; i < lines.size(); i++) {
                String escaped = escapePdfLiteral(lines.get(i));
                if (i == 0) {
                    sb.append("(").append(escaped).append(") Tj\n");
                } else {
                    sb.append("T* (").append(escaped).append(") Tj\n");
                }
            }
            sb.append("ET\n");
            return new SyntheticPageSpec(sb.toString(), null, rotationDegrees, compress);
        }

        public static SyntheticPageSpec rawStreamPage(String contentStream, int rotationDegrees, boolean compress) {
            return new SyntheticPageSpec(contentStream, null, rotationDegrees, compress);
        }

        public static SyntheticPageSpec scannedImagePage(BufferedImage image, int rotationDegrees) {
            String drawCmd = "q\n612 0 0 792 0 0 cm\n/Im1 Do\nQ\n";
            return new SyntheticPageSpec(drawCmd, image, rotationDegrees, false);
        }

        public static SyntheticPageSpec hybridPage(List<String> nativeLines, BufferedImage image) {
            StringBuilder sb = new StringBuilder();
            sb.append("q\n612 0 0 380 0 380 cm\n/Im1 Do\nQ\n");
            sb.append("BT\n/F1 11 Tf\n16 TL\n1 0 0 1 54 320 Tm\n");
            for (int i = 0; i < nativeLines.size(); i++) {
                String escaped = escapePdfLiteral(nativeLines.get(i));
                if (i == 0) {
                    sb.append("(").append(escaped).append(") Tj\n");
                } else {
                    sb.append("T* (").append(escaped).append(") Tj\n");
                }
            }
            sb.append("ET\n");
            return new SyntheticPageSpec(sb.toString(), image, 0, false);
        }
    }

    /**
     * Writes a multi-page PDF 1.4 document with valid object dictionaries, Flate/raw streams,
     * and an exact byte-offset cross-reference ({@code xref}) table.
     */
    public static Path writeSyntheticPdf(Path targetPath, List<SyntheticPageSpec> pages) throws IOException {
        if (targetPath.getParent() != null) {
            Files.createDirectories(targetPath.getParent());
        }

        int nextObjNum = 4;
        List<Integer> pageObjNums = new ArrayList<>();
        List<Integer> contentObjNums = new ArrayList<>();
        List<Integer> imageObjNums = new ArrayList<>();

        for (SyntheticPageSpec spec : pages) {
            pageObjNums.add(nextObjNum++);
            contentObjNums.add(nextObjNum++);
            if (spec.embeddedImage != null) {
                imageObjNums.add(nextObjNum++);
            } else {
                imageObjNums.add(-1);
            }
        }

        int totalObjects = nextObjNum - 1;
        List<byte[]> serializedObjects = new ArrayList<>(totalObjects + 1);
        serializedObjects.add(new byte[0]);

        serializedObjects.add(asciiBytes("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"));

        StringBuilder kids = new StringBuilder("[");
        for (int i = 0; i < pageObjNums.size(); i++) {
            if (i > 0) kids.append(" ");
            kids.append(pageObjNums.get(i)).append(" 0 R");
        }
        kids.append("]");
        serializedObjects.add(asciiBytes(
                "2 0 obj\n<< /Type /Pages /Kids " + kids + " /Count " + pages.size() + " >>\nendobj\n"));

        serializedObjects.add(asciiBytes(
                "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"));

        for (int i = 0; i < pages.size(); i++) {
            SyntheticPageSpec spec = pages.get(i);
            int pObj = pageObjNums.get(i);
            int cObj = contentObjNums.get(i);
            int imgObj = imageObjNums.get(i);

            String xobjPart = (imgObj > 0) ? " /XObject << /Im1 " + imgObj + " 0 R >>" : "";
            String rotPart = (spec.rotationDegrees != 0) ? " /Rotate " + spec.rotationDegrees : "";

            String pageDict = pObj + " 0 obj\n"
                    + "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]" + rotPart
                    + " /Contents " + cObj + " 0 R"
                    + " /Resources << /Font << /F1 3 0 R >>" + xobjPart + " >> >>\n"
                    + "endobj\n";
            serializedObjects.add(asciiBytes(pageDict));

            byte[] rawStream = spec.nativeContentStream.getBytes(StandardCharsets.ISO_8859_1);
            byte[] streamPayload = spec.compressStream ? compressFlate(rawStream) : rawStream;
            String filterPart = spec.compressStream ? " /Filter /FlateDecode" : "";

            ByteArrayOutputStream cBaos = new ByteArrayOutputStream();
            cBaos.write(asciiBytes(cObj + " 0 obj\n<< /Length " + streamPayload.length + filterPart + " >>\nstream\n"));
            cBaos.write(streamPayload);
            cBaos.write(asciiBytes("\nendstream\nendobj\n"));
            serializedObjects.add(cBaos.toByteArray());

            if (imgObj > 0 && spec.embeddedImage != null) {
                BufferedImage img = spec.embeddedImage;
                int w = img.getWidth();
                int h = img.getHeight();
                byte[] rgb = new byte[w * h * 3];
                int k = 0;
                for (int y = 0; y < h; y++) {
                    for (int x = 0; x < w; x++) {
                        int p = img.getRGB(x, y);
                        rgb[k++] = (byte) ((p >> 16) & 0xFF);
                        rgb[k++] = (byte) ((p >> 8) & 0xFF);
                        rgb[k++] = (byte) (p & 0xFF);
                    }
                }
                byte[] compRgb = compressFlate(rgb);
                ByteArrayOutputStream iBaos = new ByteArrayOutputStream();
                iBaos.write(asciiBytes(imgObj + " 0 obj\n"
                        + "<< /Type /XObject /Subtype /Image /Width " + w + " /Height " + h
                        + " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length "
                        + compRgb.length + " >>\nstream\n"));
                iBaos.write(compRgb);
                iBaos.write(asciiBytes("\nendstream\nendobj\n"));
                serializedObjects.add(iBaos.toByteArray());
            }
        }

        ByteArrayOutputStream pdfOut = new ByteArrayOutputStream();
        pdfOut.write(asciiBytes("%PDF-1.4\n"));
        int[] offsets = new int[totalObjects + 1];
        for (int objId = 1; objId <= totalObjects; objId++) {
            offsets[objId] = pdfOut.size();
            pdfOut.write(serializedObjects.get(objId));
        }

        int xrefOffset = pdfOut.size();
        StringBuilder xref = new StringBuilder();
        xref.append("xref\n0 ").append(totalObjects + 1).append("\n");
        xref.append("0000000000 65535 f \n");
        for (int objId = 1; objId <= totalObjects; objId++) {
            xref.append(String.format("%010d 00000 n \n", offsets[objId]));
        }
        xref.append("trailer\n<< /Size ").append(totalObjects + 1).append(" /Root 1 0 R >>\n");
        xref.append("startxref\n").append(xrefOffset).append("\n%%EOF\n");
        pdfOut.write(asciiBytes(xref.toString()));

        Files.write(targetPath, pdfOut.toByteArray());
        return targetPath;
    }

    /**
     * Renders synthetic lines of text onto a clean or custom-colored page scan image
     * and registers exact word coordinates for OCR testing.
     */
    public static BufferedImage createSyntheticScannedPageImage(
            List<String> lines,
            int width,
            int height,
            Color background,
            Color foreground) {
        return LocalBitmapOcrEngine.renderScannedPageImage(
                width,
                height,
                background,
                foreground,
                new Font("Monospaced", Font.BOLD, 20),
                lines,
                40,
                60,
                42,
                System.getProperty("zk.ocr.testRegistryFile"));
    }

    /**
     * Creates a low-contrast synthetic scan image where foreground text is very close in luminance
     * to the background, testing {@link ImagePreprocessor} contrast enhancement and Otsu thresholding.
     */
    public static BufferedImage createLowContrastScannedPageImage(List<String> lines) {
        BufferedImage base = LocalBitmapOcrEngine.renderScannedPageImage(
                920,
                560,
                new Color(212, 212, 212),
                new Color(168, 168, 168),
                new Font("Monospaced", Font.BOLD, 20),
                lines,
                40,
                60,
                42,
                System.getProperty("zk.ocr.testRegistryFile"));
        Graphics2D g2 = base.createGraphics();
        g2.setColor(new Color(150, 150, 150));
        g2.fillRect(10, 10, 1, 1);
        g2.fillRect(890, 520, 1, 1);
        g2.dispose();
        return base;
    }

    private static String escapePdfLiteral(String s) {
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)");
    }

    private static byte[] asciiBytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] compressFlate(byte[] input) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        deflater.setInput(input);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length + 64);
        byte[] buf = new byte[4096];
        while (!deflater.finished()) {
            int n = deflater.deflate(buf);
            if (n > 0) {
                baos.write(buf, 0, n);
            } else {
                break;
            }
        }
        deflater.end();
        return baos.toByteArray();
    }
}
