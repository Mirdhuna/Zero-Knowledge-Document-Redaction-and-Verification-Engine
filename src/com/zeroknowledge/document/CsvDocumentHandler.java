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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * RFC-4180 compliant CSV document handler ({@code .csv}).
 *
 * <h3>Capabilities & Guarantees</h3>
 * <ul>
 *   <li>Uses a full character-by-character state-machine parser (never {@code String.split(",")}).</li>
 *   <li>Correctly parses quoted fields, escaped double quotes ({@code ""}), embedded commas, and multiline fields ({@code \n} / {@code \r\n}).</li>
 *   <li>Rejects malformed CSV inputs (unclosed quotes, unescaped quotes inside fields, or characters trailing a closing quote before a delimiter).</li>
 *   <li>Applies redactions strictly inside target {@code (rowIndex, columnIndex)} cells before re-serializing valid RFC-4180 CSV, ensuring values never shift across columns or rows.</li>
 * </ul>
 */
public final class CsvDocumentHandler implements DocumentHandler {

    private final FileStorageService fileStorageService;
    private final HashService hashService;
    private final char delimiter;

    public CsvDocumentHandler(FileStorageService fileStorageService, HashService hashService, char delimiter) {
        this.fileStorageService = Objects.requireNonNull(fileStorageService, "fileStorageService must not be null");
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
        if (delimiter == '"' || delimiter == '\r' || delimiter == '\n') {
            throw new IllegalArgumentException("Invalid CSV delimiter character");
        }
        this.delimiter = delimiter;
    }

    public CsvDocumentHandler(FileStorageService fileStorageService, HashService hashService) {
        this(fileStorageService, hashService, ',');
    }

    @Override
    public DocumentFormat getSupportedFormat() {
        return DocumentFormat.CSV;
    }

    @Override
    public String readValidatedContent(Path sourcePath) throws DocumentProcessingException {
        Path normalized = fileStorageService.validateReadableSourceFile(sourcePath);
        if (DocumentFormat.fromPath(normalized) != DocumentFormat.CSV) {
            throw new DocumentProcessingException(
                    "CsvDocumentHandler only supports .csv files: " + normalized.getFileName());
        }
        String rawText = fileStorageService.readUtf8Text(normalized);
        // Validate CSV structure on read
        parseCsvRecords(rawText, delimiter);
        return rawText;
    }

    @Override
    public List<RedactionMatch> scan(Path sourcePath, SensitiveDataDetector detector)
            throws DocumentProcessingException {
        Objects.requireNonNull(detector, "detector must not be null");
        Path normalized = fileStorageService.validateReadableSourceFile(sourcePath);
        if (DocumentFormat.fromPath(normalized) != DocumentFormat.CSV) {
            throw new DocumentProcessingException(
                    "CsvDocumentHandler only supports .csv files: " + normalized.getFileName());
        }
        String rawText = fileStorageService.readUtf8Text(normalized);
        if (rawText.isEmpty()) {
            return List.of();
        }

        List<List<String>> records = parseCsvRecords(rawText, delimiter);
        List<RedactionMatch> allMatches = new ArrayList<>();
        for (int row = 0; row < records.size(); row++) {
            List<String> columns = records.get(row);
            for (int col = 0; col < columns.size(); col++) {
                String cellValue = columns.get(col);
                if (cellValue != null && !cellValue.isEmpty()) {
                    allMatches.addAll(detector.detectInCell(cellValue, row, col));
                }
            }
        }
        return Collections.unmodifiableList(allMatches);
    }

    @Override
    public RedactionResult applyRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException {
        Path normalizedSource = fileStorageService.validateReadableSourceFile(sourcePath);
        if (DocumentFormat.fromPath(normalizedSource) != DocumentFormat.CSV) {
            throw new DocumentProcessingException(
                    "CsvDocumentHandler only supports .csv files: " + normalizedSource.getFileName());
        }

        String rawText = fileStorageService.readUtf8Text(normalizedSource);
        String lineSeparator = rawText.contains("\r\n") ? "\r\n" : "\n";
        boolean trailingNewline = rawText.endsWith("\n");

        List<List<String>> records = parseCsvRecords(rawText, delimiter);
        List<RedactionMatch> candidates = (approvedMatches == null) ? List.of() : approvedMatches;

        // Group approved matches by (rowIndex, columnIndex)
        Map<String, List<RedactionMatch>> matchesByCell = new HashMap<>();
        for (RedactionMatch match : candidates) {
            if (match != null && match.isSelectedForRedaction()) {
                if (!match.isCellScoped()) {
                    throw new RedactionException(
                            "CSV redaction match must specify valid non-negative rowIndex and columnIndex: "
                                    + match.getMatchId());
                }
                int r = match.getRowIndex();
                int c = match.getColumnIndex();
                if (r < 0 || r >= records.size()) {
                    throw new RedactionException("CSV match rowIndex " + r + " is out of bounds (total rows: " + records.size() + ")");
                }
                List<String> rowCells = records.get(r);
                if (c < 0 || c >= rowCells.size()) {
                    throw new RedactionException(
                            "CSV match columnIndex " + c + " is out of bounds for row " + r + " (columns: " + rowCells.size() + ")");
                }
                String key = r + ":" + c;
                matchesByCell.computeIfAbsent(key, k -> new ArrayList<>()).add(match);
            }
        }

        List<List<String>> redactedRecords = new ArrayList<>(records.size());
        List<RedactionMatch> allApplied = new ArrayList<>();

        for (int r = 0; r < records.size(); r++) {
            List<String> originalRow = records.get(r);
            List<String> newRow = new ArrayList<>(originalRow.size());
            for (int c = 0; c < originalRow.size(); c++) {
                String originalCell = originalRow.get(c);
                List<RedactionMatch> cellMatches = matchesByCell.get(r + ":" + c);
                if (cellMatches == null || cellMatches.isEmpty()) {
                    newRow.add(originalCell);
                } else {
                    ResolvedRedaction resolved = DocumentHandler.applyMatchesToText(originalCell, cellMatches);
                    newRow.add(resolved.getRedactedText());
                    allApplied.addAll(resolved.getAppliedMatches());
                }
            }
            redactedRecords.add(newRow);
        }

        String serializedCsv = serializeCsvRecords(redactedRecords, delimiter, lineSeparator, trailingNewline);
        Path targetOutput = (outputPath != null)
                ? outputPath
                : fileStorageService.resolveDefaultRedactedOutputPath(normalizedSource);

        Path savedPath = fileStorageService.writeRedactedUtf8Safely(normalizedSource, targetOutput, serializedCsv, true);

        // Post-save structural verification: parse the saved CSV and verify row & column dimensions match
        String reloadedCsv = fileStorageService.readUtf8Text(savedPath);
        List<List<String>> reloadedRecords = parseCsvRecords(reloadedCsv, delimiter);
        if (reloadedRecords.size() != redactedRecords.size()) {
            throw new RedactionException("Post-save CSV row count verification failed");
        }
        for (int r = 0; r < redactedRecords.size(); r++) {
            if (!reloadedRecords.get(r).equals(redactedRecords.get(r))) {
                throw new RedactionException("Post-save CSV cell integrity verification failed at row " + r);
            }
        }

        String sourceHash = hashService.calculateSha256(normalizedSource);
        String outputHash = hashService.calculateSha256(savedPath);

        return new RedactionResult(
                true,
                DocumentFormat.CSV,
                normalizedSource,
                savedPath,
                sourceHash,
                outputHash,
                candidates.size(),
                allApplied.size(),
                allApplied,
                Instant.now(),
                "Successfully applied " + allApplied.size()
                        + " user-approved cell redaction(s) across " + redactedRecords.size() + " CSV row(s).");
    }

    /**
     * Parses RFC-4180 CSV text into rows and columns using a strict state machine.
     *
     * @throws DocumentProcessingException if unclosed quotes or invalid quote placement are encountered
     */
    public static List<List<String>> parseCsvRecords(String csvContent, char delimiter)
            throws DocumentProcessingException {
        Objects.requireNonNull(csvContent, "csvContent must not be null");
        if (csvContent.isEmpty()) {
            return List.of();
        }

        List<List<String>> rows = new ArrayList<>();
        List<String> currentRow = new ArrayList<>();
        StringBuilder currentCell = new StringBuilder();

        enum State {
            START_FIELD,
            IN_UNQUOTED_FIELD,
            IN_QUOTED_FIELD,
            AFTER_CLOSING_QUOTE
        }

        State state = State.START_FIELD;
        int len = csvContent.length();

        for (int i = 0; i < len; i++) {
            char ch = csvContent.charAt(i);
            switch (state) {
                case START_FIELD -> {
                    if (ch == '"') {
                        state = State.IN_QUOTED_FIELD;
                    } else if (ch == delimiter) {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        state = State.START_FIELD;
                    } else if (ch == '\r') {
                        if (i + 1 < len && csvContent.charAt(i + 1) == '\n') {
                            i++;
                        }
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else if (ch == '\n') {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else {
                        currentCell.append(ch);
                        state = State.IN_UNQUOTED_FIELD;
                    }
                }
                case IN_UNQUOTED_FIELD -> {
                    if (ch == '"') {
                        throw new DocumentProcessingException(
                                "Malformed CSV: unescaped quote inside unquoted field at character offset " + i);
                    } else if (ch == delimiter) {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        state = State.START_FIELD;
                    } else if (ch == '\r') {
                        if (i + 1 < len && csvContent.charAt(i + 1) == '\n') {
                            i++;
                        }
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else if (ch == '\n') {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else {
                        currentCell.append(ch);
                    }
                }
                case IN_QUOTED_FIELD -> {
                    if (ch == '"') {
                        if (i + 1 < len && csvContent.charAt(i + 1) == '"') {
                            // Escaped quote ""
                            currentCell.append('"');
                            i++;
                        } else {
                            state = State.AFTER_CLOSING_QUOTE;
                        }
                    } else {
                        currentCell.append(ch);
                    }
                }
                case AFTER_CLOSING_QUOTE -> {
                    if (ch == delimiter) {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        state = State.START_FIELD;
                    } else if (ch == '\r') {
                        if (i + 1 < len && csvContent.charAt(i + 1) == '\n') {
                            i++;
                        }
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else if (ch == '\n') {
                        currentRow.add(currentCell.toString());
                        currentCell.setLength(0);
                        rows.add(currentRow);
                        currentRow = new ArrayList<>();
                        state = State.START_FIELD;
                    } else {
                        throw new DocumentProcessingException(
                                "Malformed CSV: unexpected character after closing quote at offset " + i);
                    }
                }
            }
        }

        if (state == State.IN_QUOTED_FIELD) {
            throw new DocumentProcessingException("Malformed CSV: unclosed quoted field at end of document");
        }

        // Flush final row unless the file ended cleanly on a newline with an empty pending row
        boolean endedWithNewline = csvContent.endsWith("\n") || csvContent.endsWith("\r");
        if (!endedWithNewline || !currentRow.isEmpty() || currentCell.length() > 0) {
            currentRow.add(currentCell.toString());
            rows.add(currentRow);
        }

        return rows;
    }

    /**
     * Serializes rows and cells into RFC-4180 compliant CSV format.
     */
    public static String serializeCsvRecords(
            List<List<String>> records,
            char delimiter,
            String lineSeparator,
            boolean trailingNewline) {
        if (records == null || records.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int r = 0; r < records.size(); r++) {
            List<String> row = records.get(r);
            for (int c = 0; c < row.size(); c++) {
                if (c > 0) {
                    sb.append(delimiter);
                }
                String cell = row.get(c) == null ? "" : row.get(c);
                sb.append(formatCsvCell(cell, delimiter));
            }
            if (r < records.size() - 1 || trailingNewline) {
                sb.append(lineSeparator);
            }
        }
        return sb.toString();
    }

    private static String formatCsvCell(String cell, char delimiter) {
        boolean mustQuote = false;
        for (int i = 0; i < cell.length(); i++) {
            char ch = cell.charAt(i);
            if (ch == delimiter || ch == '"' || ch == '\n' || ch == '\r') {
                mustQuote = true;
                break;
            }
        }
        if (!mustQuote && !cell.isEmpty() && (Character.isWhitespace(cell.charAt(0))
                || Character.isWhitespace(cell.charAt(cell.length() - 1)))) {
            mustQuote = true;
        }
        if (!mustQuote) {
            return cell;
        }
        String escaped = cell.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }
}
