package com.zeroknowledge.document;

import com.zeroknowledge.document.ImagePreprocessor.PreprocessedImage;
import com.zeroknowledge.model.PdfBoundingBox;
import com.zeroknowledge.storage.ApplicationConfig;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.imageio.ImageIO;

/**
 * Genuine local Tesseract OCR integration using a safe {@link ProcessBuilder} process wrapper.
 *
 * <h3>Capabilities &amp; Guarantees</h3>
 * <ul>
 *   <li>Strictly local execution — never transmits document images over any network.</li>
 *   <li>Auto-discovers {@code tesseract} on system {@code PATH}, {@code TESSERACT_PATH},
 *       {@code -Dzk.ocr.tesseractPath}, and standard Windows/Linux installation paths.</li>
 *   <li>Verifies availability of the configured OCR language pack (e.g., {@code eng.traineddata})
 *       using {@code tesseract --list-langs}.</li>
 *   <li>Preprocesses scanned images via {@link ImagePreprocessor} (upscaling, grayscale,
 *       contrast stretching, impulse denoising, deskewing, Otsu thresholding) prior to OCR.</li>
 *   <li>Executes {@code tesseract <image.png> stdout -l <lang> --psm 6 tsv} and parses word-level
 *       bounding boxes and confidence values, mapping coordinates back to original image pixels
 *       and PDF page user-space points.</li>
 * </ul>
 */
public final class TesseractOcrEngine implements OcrEngine {

    public static final String SETUP_INSTRUCTIONS =
            "Local Tesseract OCR Setup Instructions:\n"
            + "• Windows:\n"
            + "  1. Install via Winget: winget install --id UB-Mannheim.TesseractOCR\n"
            + "     (or download installer from https://github.com/UB-Mannheim/tesseract/wiki)\n"
            + "  2. Ensure 'C:\\Program Files\\Tesseract-OCR' is on your PATH, or set environment variable:\n"
            + "     set TESSERACT_PATH=C:\\Program Files\\Tesseract-OCR\\tesseract.exe\n"
            + "  3. Verify 'eng.traineddata' exists in 'C:\\Program Files\\Tesseract-OCR\\tessdata'.\n"
            + "• Linux (Ubuntu / Debian / Kali / Fedora):\n"
            + "  1. Install Tesseract & English language data:\n"
            + "     sudo apt update && sudo apt install -y tesseract-ocr tesseract-ocr-eng\n"
            + "     (or on Fedora/RHEL: sudo dnf install -y tesseract tesseract-langpack-eng)\n"
            + "  2. Verify installation: tesseract --version && tesseract --list-langs";

    private static final long PROCESS_TIMEOUT_SECONDS = 30L;

    private final ApplicationConfig config;
    private volatile OcrAvailability cachedAvailability;

    public TesseractOcrEngine(ApplicationConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    public TesseractOcrEngine() {
        this(ApplicationConfig.createDefault());
    }

    /**
     * Clears any cached availability status so a fresh check is performed.
     */
    public void resetAvailabilityCache() {
        this.cachedAvailability = null;
    }

    @Override
    public OcrAvailability checkAvailability() {
        OcrAvailability cached = this.cachedAvailability;
        if (cached != null) {
            return cached;
        }
        OcrAvailability computed = probeTesseractAvailability();
        this.cachedAvailability = computed;
        return computed;
    }

    private OcrAvailability probeTesseractAvailability() {
        String lang = config.getOcrLanguage();
        String executable = resolveExecutableCandidate();
        if (executable == null || executable.isBlank()) {
            return new OcrAvailability(
                    false,
                    "",
                    "",
                    lang,
                    false,
                    "Tesseract OCR executable ('tesseract') was not found on PATH or standard install locations.",
                    SETUP_INSTRUCTIONS);
        }

        // 1. Check --version
        List<String> versionCmd = buildCommandPrefix(executable);
        versionCmd.add("--version");
        ProcessOutput versionOut = runProcessSafely(versionCmd, 10L);
        if (!versionOut.completed || versionOut.exitCode != 0) {
            return new OcrAvailability(
                    false,
                    executable,
                    "",
                    lang,
                    false,
                    "Tesseract OCR executable could not be executed (" + executable + ").",
                    SETUP_INSTRUCTIONS);
        }

        String firstVersionLine = versionOut.stdout.lines().findFirst().orElse("tesseract").trim();

        // 2. Check --list-langs to ensure required language pack is installed
        List<String> langCmd = buildCommandPrefix(executable);
        if (!config.getTessdataDirectory().isBlank()) {
            langCmd.add("--tessdata-dir");
            langCmd.add(config.getTessdataDirectory());
        }
        langCmd.add("--list-langs");

        ProcessOutput langOut = runProcessSafely(langCmd, 10L);
        Set<String> installedLangs = new HashSet<>();
        String combinedLangOutput = langOut.stdout + "\n" + langOut.stderr;
        for (String line : combinedLangOutput.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.toLowerCase(Locale.ROOT).startsWith("list of available")) {
                installedLangs.add(trimmed.toLowerCase(Locale.ROOT));
            }
        }

        String[] requiredLangs = lang.toLowerCase(Locale.ROOT).split("\\+");
        List<String> missingLangs = new ArrayList<>();
        for (String req : requiredLangs) {
            String cleanReq = req.trim();
            if (!cleanReq.isEmpty() && !installedLangs.isEmpty() && !installedLangs.contains(cleanReq)) {
                missingLangs.add(cleanReq);
            }
        }

        if (!missingLangs.isEmpty()) {
            return new OcrAvailability(
                    false,
                    executable,
                    firstVersionLine,
                    lang,
                    false,
                    "Tesseract OCR is installed (" + firstVersionLine + "), but required language data '"
                            + String.join("+", missingLangs) + ".traineddata' is missing in tessdata.",
                    SETUP_INSTRUCTIONS);
        }

        return new OcrAvailability(
                true,
                executable,
                firstVersionLine,
                lang,
                true,
                "Tesseract OCR ready (" + firstVersionLine + ", lang=" + lang + ")",
                "");
    }

    @Override
    public OcrExtractionResult recognizeImage(
            BufferedImage image,
            int pageNumber,
            PdfBoundingBox imagePlacementOnPage,
            double fullPageWidthPts,
            double fullPageHeightPts,
            int pageRotation) {
        if (image == null || image.getWidth() <= 0 || image.getHeight() <= 0) {
            return OcrExtractionResult.failed("Invalid or empty image supplied for OCR on page " + pageNumber);
        }

        OcrAvailability availability = checkAvailability();
        if (!availability.isAvailable()) {
            return OcrExtractionResult.unavailable(availability.getStatusMessage());
        }

        // Preprocess image (upscaling, grayscale, contrast stretch, denoising, deskewing, Otsu thresholding)
        PreprocessedImage preprocessed = ImagePreprocessor.preprocess(image, config.getOcrRenderDpi());

        Path tempPng = null;
        try {
            tempPng = Files.createTempFile("zk_ocr_p" + pageNumber + "_", ".png");
            boolean written = ImageIO.write(preprocessed.getImage(), "PNG", tempPng.toFile());
            if (!written) {
                return OcrExtractionResult.failed("Failed to encode preprocessed page image to PNG for OCR");
            }

            List<String> cmd = buildCommandPrefix(availability.getExecutablePath());
            cmd.add(tempPng.toAbsolutePath().toString());
            cmd.add("stdout");
            cmd.add("-l");
            cmd.add(config.getOcrLanguage());
            if (!config.getTessdataDirectory().isBlank()) {
                cmd.add("--tessdata-dir");
                cmd.add(config.getTessdataDirectory());
            }
            cmd.add("--psm");
            cmd.add("6");
            cmd.add("tsv");

            ProcessOutput out = runProcessSafely(cmd, PROCESS_TIMEOUT_SECONDS);
            if (!out.completed) {
                return OcrExtractionResult.failed("Tesseract OCR timed out on page " + pageNumber);
            }
            if (out.exitCode != 0) {
                return OcrExtractionResult.failed(
                        "Tesseract OCR exited with code " + out.exitCode + " on page " + pageNumber);
            }

            return parseTsvOutput(
                    out.stdout,
                    preprocessed,
                    pageNumber,
                    imagePlacementOnPage,
                    fullPageWidthPts,
                    fullPageHeightPts,
                    pageRotation);
        } catch (IOException e) {
            return OcrExtractionResult.failed(
                    "I/O failure during local OCR execution on page " + pageNumber + ": " + e.getMessage());
        } finally {
            if (tempPng != null) {
                try {
                    Files.deleteIfExists(tempPng);
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Parses standard 12-column Tesseract TSV output into structured word bounding boxes
     * and reconstructed page text.
     */
    public static OcrExtractionResult parseTsvOutput(
            String tsvContent,
            PreprocessedImage preprocessed,
            int pageNumber,
            PdfBoundingBox imagePlacementOnPage,
            double fullPageWidthPts,
            double fullPageHeightPts,
            int pageRotation) {
        if (tsvContent == null || tsvContent.isBlank()) {
            return new OcrExtractionResult(true, false, "", 1.0, List.of(), "OCR completed (no text found)");
        }

        StringBuilder fullText = new StringBuilder();
        List<OcrWordBox> wordBoxes = new ArrayList<>();
        double confSum = 0.0;
        int confCount = 0;

        String lastLineKey = null;
        int currentLineId = 0;

        String[] lines = tsvContent.split("\\r?\\n");
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("level\t")) {
                continue;
            }
            String[] cols = line.split("\t", 12);
            if (cols.length < 12) {
                continue;
            }
            try {
                int level = Integer.parseInt(cols[0].trim());
                if (level != 5) {
                    continue; // Level 5 = word level in Tesseract TSV
                }
                int blockNum = Integer.parseInt(cols[2].trim());
                int parNum = Integer.parseInt(cols[3].trim());
                int lineNum = Integer.parseInt(cols[4].trim());
                int left = Integer.parseInt(cols[6].trim());
                int top = Integer.parseInt(cols[7].trim());
                int width = Integer.parseInt(cols[8].trim());
                int height = Integer.parseInt(cols[9].trim());
                double rawConf = Double.parseDouble(cols[10].trim());
                String wordText = cols[11].trim();

                if (wordText.isEmpty() || rawConf < 0 || width <= 0 || height <= 0) {
                    continue;
                }

                double normConf = Math.max(0.0, Math.min(1.0, rawConf > 1.0 ? rawConf / 100.0 : rawConf));
                String lineKey = blockNum + ":" + parNum + ":" + lineNum;
                if (lastLineKey == null) {
                    lastLineKey = lineKey;
                    currentLineId = 1;
                } else if (!lastLineKey.equals(lineKey)) {
                    fullText.append('\n');
                    lastLineKey = lineKey;
                    currentLineId++;
                } else if (fullText.length() > 0) {
                    fullText.append(' ');
                }

                int startOffset = fullText.length();
                fullText.append(wordText);
                int endOffset = fullText.length();

                Rectangle origPixelRect = preprocessed.mapToOriginalPixels(left, top, width, height);
                PdfBoundingBox pdfBox = PdfBoundingBox.fromImagePixels(
                        pageNumber,
                        origPixelRect.x,
                        origPixelRect.y,
                        origPixelRect.width,
                        origPixelRect.height,
                        preprocessed.getOriginalWidth(),
                        preprocessed.getOriginalHeight(),
                        imagePlacementOnPage,
                        fullPageWidthPts,
                        fullPageHeightPts,
                        pageRotation);

                wordBoxes.add(new OcrWordBox(
                        wordText,
                        normConf,
                        startOffset,
                        endOffset,
                        currentLineId,
                        origPixelRect,
                        pdfBox));

                confSum += normConf;
                confCount++;
            } catch (NumberFormatException ignored) {
                // Skip malformed TSV row
            }
        }

        double avgConf = confCount > 0 ? (confSum / confCount) : 1.0;
        String diag = String.format(Locale.ROOT,
                "OCR extracted %d word(s) on page %d (avg confidence: %.0f%%)",
                wordBoxes.size(), pageNumber, avgConf * 100.0);

        return new OcrExtractionResult(
                true,
                false,
                fullText.toString(),
                avgConf,
                wordBoxes,
                diag);
    }

    private String resolveExecutableCandidate() {
        String configured = config.getTesseractExecutablePath();
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        String sysProp = System.getProperty("zk.ocr.tesseractPath");
        if (sysProp != null && !sysProp.isBlank()) {
            return sysProp.trim();
        }
        String envPath = System.getenv("TESSERACT_PATH");
        if (envPath != null && !envPath.isBlank()) {
            return envPath.trim();
        }

        // Check standard OS paths
        String localAppData = System.getenv("LOCALAPPDATA");
        List<Path> standardPaths = new ArrayList<>();
        standardPaths.add(Path.of("C:\\Program Files\\Tesseract-OCR\\tesseract.exe"));
        standardPaths.add(Path.of("C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe"));
        if (localAppData != null && !localAppData.isBlank()) {
            standardPaths.add(Path.of(localAppData, "Programs", "Tesseract-OCR", "tesseract.exe"));
            standardPaths.add(Path.of(localAppData, "Tesseract-OCR", "tesseract.exe"));
        }
        standardPaths.add(Path.of("/usr/bin/tesseract"));
        standardPaths.add(Path.of("/usr/local/bin/tesseract"));
        standardPaths.add(Path.of("/opt/homebrew/bin/tesseract"));

        for (Path candidate : standardPaths) {
            if (Files.exists(candidate) && Files.isRegularFile(candidate)) {
                return candidate.toAbsolutePath().toString();
            }
        }

        // Fallback to PATH lookup
        ProcessOutput pathCheck = runProcessSafely(List.of("tesseract", "--version"), 5L);
        if (pathCheck.completed && pathCheck.exitCode == 0) {
            return "tesseract";
        }
        return null;
    }

    private static List<String> buildCommandPrefix(String executable) {
        List<String> cmd = new ArrayList<>();
        String lower = executable.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".bat") || lower.endsWith(".cmd")) {
            cmd.add("cmd.exe");
            cmd.add("/c");
            cmd.add(executable);
        } else if (lower.endsWith(".sh") && !System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")) {
            cmd.add("/bin/sh");
            cmd.add(executable);
        } else {
            cmd.add(executable);
        }
        return cmd;
    }

    private record ProcessOutput(boolean completed, int exitCode, String stdout, String stderr) {}

    private static ProcessOutput runProcessSafely(List<String> command, long timeoutSeconds) {
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            process = pb.start();

            final Process p = process;
            StringBuilder stdoutSb = new StringBuilder();
            StringBuilder stderrSb = new StringBuilder();

            Thread outThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        stdoutSb.append(line).append('\n');
                    }
                } catch (IOException ignored) {
                }
            }, "zk-ocr-stdout");
            outThread.setDaemon(true);

            Thread errThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        stderrSb.append(line).append('\n');
                    }
                } catch (IOException ignored) {
                }
            }, "zk-ocr-stderr");
            errThread.setDaemon(true);

            outThread.start();
            errThread.start();

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new ProcessOutput(false, -1, "", "Process timed out");
            }
            outThread.join(2000L);
            errThread.join(2000L);
            return new ProcessOutput(true, process.exitValue(), stdoutSb.toString(), stderrSb.toString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new ProcessOutput(false, -1, "", e.getMessage() == null ? "Execution error" : e.getMessage());
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
