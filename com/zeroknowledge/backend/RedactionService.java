package com.zeroknowledge.backend;

import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Backend service for sensitive data scanning and document redaction.
 * Uses Java standard library regex engines and NIO utilities.
 */
public class RedactionService {

    public static class PatternRule {
        private final String type;
        private final Pattern pattern;
        private final String description;

        public PatternRule(String type, String regex, String description) {
            this.type = type;
            this.pattern = Pattern.compile(regex);
            this.description = description;
        }

        public String getType() {
            return type;
        }

        public Pattern getPattern() {
            return pattern;
        }

        public String getDescription() {
            return description;
        }
    }

    private final List<PatternRule> rules = new ArrayList<>();
    private static final Set<String> SUPPORTED_EXTENSIONS = Set.of("txt", "csv", "log", "json", "md", "tsv");

    public RedactionService() {
        initDefaultRules();
    }

    private void initDefaultRules() {
        // Email address
        rules.add(new PatternRule(
                "EMAIL",
                "(?i)\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
                "Email address conforming to standard internet formats"
        ));

        // US Social Security Number (with dashes)
        rules.add(new PatternRule(
                "SSN",
                "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                "US Social Security Number (9-digit format with delimiters)"
        ));

        // Credit / Debit card number (16 digits with optional spaces or dashes)
        rules.add(new PatternRule(
                "CREDIT_CARD",
                "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\\d{3})\\d{11}|(?:\\d{4}[ -]?){3}\\d{4})\\b",
                "Standard 13 to 16 digit payment card number"
        ));

        // Phone number
        rules.add(new PatternRule(
                "PHONE",
                "\\b(?:\\+?\\d{1,3}[-.\s]?)?\\(?\\d{3}\\)?[-.\s]?\\d{3}[-.\s]?\\d{4}\\b",
                "Telephone or mobile contact number"
        ));

        // API Key / Secret tokens
        rules.add(new PatternRule(
                "API_KEY",
                "\\b(?:sec_token_[0-9a-zA-Z]{20,}|api_key_[0-9a-zA-Z]{20,}|auth_key_[0-9a-zA-Z]{20,}|bearer\\s+[A-Za-z0-9_.-]{20,})\\b",
                "Cryptographic API access token or secret token"
        ));

        // IPv4 Address
        rules.add(new PatternRule(
                "IP_ADDRESS",
                "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
                "IPv4 network address"
        ));
    }

    public List<PatternRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public boolean isSupportedForRedaction(File file) {
        if (file == null) return false;
        String name = file.getName();
        int dot = name.lastIndexOf('.');
        if (dot < 0) return false;
        String ext = name.substring(dot + 1).toLowerCase();
        return SUPPORTED_EXTENSIONS.contains(ext);
    }

    public boolean isPdf(File file) {
        if (file == null) return false;
        return file.getName().toLowerCase().endsWith(".pdf");
    }

    public String getPdfLimitationExplanation() {
        return "PDF redaction is not supported in this runtime environment. Standard JDK 21 does not provide a native PDF parsing and text-replacement engine. A visual overlay without deep binary stream redaction would create a false sense of security, leaving underlying data extractable.";
    }

    /**
     * Scans a supported document for sensitive information.
     */
    public List<RedactionMatch> scanDocument(File file, Set<String> enabledPatternTypes) throws IOException {
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("Document file does not exist.");
        }

        if (isPdf(file)) {
            throw new UnsupportedOperationException(getPdfLimitationExplanation());
        }

        if (!isSupportedForRedaction(file)) {
            throw new IllegalArgumentException("Unsupported document format: " + file.getName() +
                    ". Supported formats: " + String.join(", ", SUPPORTED_EXTENSIONS));
        }

        List<RedactionMatch> matches = new ArrayList<>();
        List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);

        int matchCounter = 1;
        int currentCharOffset = 0;

        for (int lineIdx = 0; lineIdx < lines.size(); lineIdx++) {
            String line = lines.get(lineIdx);
            int lineNumber = lineIdx + 1;

            for (PatternRule rule : rules) {
                if (enabledPatternTypes != null && !enabledPatternTypes.isEmpty() &&
                        !enabledPatternTypes.contains(rule.getType())) {
                    continue;
                }

                Matcher matcher = rule.getPattern().matcher(line);
                while (matcher.find()) {
                    String raw = matcher.group();
                    int startCol = matcher.start() + 1;
                    int endCol = matcher.end();
                    int startOffset = currentCharOffset + matcher.start();
                    int endOffset = currentCharOffset + matcher.end();

                    String masked = maskValue(raw, rule.getType());
                    String id = "M" + (matchCounter++);

                    matches.add(new RedactionMatch(
                            id,
                            rule.getType(),
                            raw,
                            masked,
                            startOffset,
                            endOffset,
                            lineNumber,
                            startCol,
                            rule.getDescription()
                    ));
                }
            }

            currentCharOffset += line.length() + System.lineSeparator().length();
        }

        // Sort matches by line and column
        matches.sort(Comparator.comparingInt(RedactionMatch::getLineNumber)
                .thenComparingInt(RedactionMatch::getColumnNumber));

        return matches;
    }

    /**
     * Creates a privacy-preserving masked preview for sensitive values.
     */
    public String maskValue(String raw, String type) {
        if (raw == null || raw.isEmpty()) return "***";
        int len = raw.length();

        switch (type) {
            case "EMAIL": {
                int atIdx = raw.indexOf('@');
                if (atIdx > 2) {
                    return raw.substring(0, 2) + "***" + raw.substring(atIdx);
                } else if (atIdx > 0) {
                    return raw.charAt(0) + "***" + raw.substring(atIdx);
                }
                return "***@***";
            }
            case "SSN": {
                if (raw.contains("-") && len == 11) {
                    return "***-**-" + raw.substring(7);
                }
                return "***-**-" + (len >= 4 ? raw.substring(len - 4) : "***");
            }
            case "CREDIT_CARD": {
                String digits = raw.replaceAll("[^0-9]", "");
                if (digits.length() >= 4) {
                    return "****-****-****-" + digits.substring(digits.length() - 4);
                }
                return "****-****-****-****";
            }
            case "PHONE": {
                if (len >= 4) {
                    return "***-***-" + raw.substring(len - 4);
                }
                return "***-***-****";
            }
            case "API_KEY": {
                if (len > 8) {
                    return raw.substring(0, 4) + "..." + raw.substring(len - 4);
                }
                return "**********";
            }
            case "IP_ADDRESS": {
                int firstDot = raw.indexOf('.');
                if (firstDot > 0) {
                    return raw.substring(0, firstDot) + ".*.*.*";
                }
                return "*.*.*.*";
            }
            default:
                if (len <= 4) return "[REDACTED]";
                return raw.charAt(0) + "[REDACTED]" + raw.charAt(len - 1);
        }
    }

    /**
     * Applies approved redactions to the input file and writes the sanitized output file.
     */
    public RedactionResult applyRedaction(File inputFile, File outputFile,
                                          List<RedactionMatch> approvedMatches,
                                          boolean signOutput,
                                          KeyPair signingKeyPair,
                                          CryptoService cryptoService) throws IOException {
        if (inputFile == null || !inputFile.exists()) {
            return RedactionResult.failure(
                    inputFile != null ? inputFile.getAbsolutePath() : "",
                    "Input file does not exist."
            );
        }

        if (outputFile == null) {
            return RedactionResult.failure(inputFile.getAbsolutePath(), "Output destination not specified.");
        }

        if (outputFile.getAbsolutePath().equals(inputFile.getAbsolutePath())) {
            return RedactionResult.failure(inputFile.getAbsolutePath(),
                    "Security policy violation: Redacted output cannot overwrite the original file.");
        }

        // Calculate original SHA-256
        String originalSha256;
        try {
            originalSha256 = cryptoService.calculateSha256(inputFile);
        } catch (Exception e) {
            return RedactionResult.failure(inputFile.getAbsolutePath(), "Failed to hash original file: " + e.getMessage());
        }

        // Group approved matches by line
        Map<Integer, List<RedactionMatch>> matchesByLine = new HashMap<>();
        int appliedCount = 0;
        for (RedactionMatch match : approvedMatches) {
            if (match.isSelected()) {
                matchesByLine.computeIfAbsent(match.getLineNumber(), k -> new ArrayList<>()).add(match);
                appliedCount++;
            }
        }

        // Read lines and perform replacement
        List<String> originalLines = Files.readAllLines(inputFile.toPath(), StandardCharsets.UTF_8);
        List<String> redactedLines = new ArrayList<>(originalLines.size());

        for (int lineIdx = 0; lineIdx < originalLines.size(); lineIdx++) {
            int lineNum = lineIdx + 1;
            String line = originalLines.get(lineIdx);
            List<RedactionMatch> lineMatches = matchesByLine.get(lineNum);

            if (lineMatches == null || lineMatches.isEmpty()) {
                redactedLines.add(line);
            } else {
                // Sort by column descending to replace from right to left without shifting column offsets
                lineMatches.sort((a, b) -> Integer.compare(b.getColumnNumber(), a.getColumnNumber()));
                StringBuilder sb = new StringBuilder(line);

                for (RedactionMatch m : lineMatches) {
                    int startCol0 = m.getColumnNumber() - 1;
                    int endCol0 = startCol0 + m.getRawValue().length();
                    if (startCol0 >= 0 && endCol0 <= sb.length()) {
                        String replacement = "[REDACTED:" + m.getCandidateType() + "]";
                        sb.replace(startCol0, endCol0, replacement);
                    }
                }
                redactedLines.add(sb.toString());
            }
        }

        // Ensure parent directory exists
        File parent = outputFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        // Write output
        Files.write(outputFile.toPath(), redactedLines, StandardCharsets.UTF_8);

        // Calculate redacted SHA-256
        String redactedSha256;
        try {
            redactedSha256 = cryptoService.calculateSha256(outputFile);
        } catch (Exception e) {
            return RedactionResult.failure(inputFile.getAbsolutePath(), "Failed to hash redacted output: " + e.getMessage());
        }

        // Digital signing if requested
        boolean isSigned = false;
        String signaturePath = null;
        if (signOutput) {
            if (signingKeyPair == null || signingKeyPair.getPrivate() == null) {
                return RedactionResult.failure(inputFile.getAbsolutePath(),
                        "Signing requested, but no active private key was provided.");
            }
            try {
                File sigFile = new File(outputFile.getAbsolutePath() + ".sig");
                cryptoService.signDocument(outputFile, signingKeyPair.getPrivate(), sigFile);
                isSigned = true;
                signaturePath = sigFile.getAbsolutePath();
            } catch (Exception e) {
                return new RedactionResult(false, inputFile.getAbsolutePath(), outputFile.getAbsolutePath(),
                        approvedMatches.size(), appliedCount, originalSha256, redactedSha256,
                        false, null, "Document redacted successfully, but signing failed: " + e.getMessage());
            }
        }

        return new RedactionResult(
                true,
                inputFile.getAbsolutePath(),
                outputFile.getAbsolutePath(),
                approvedMatches.size(),
                appliedCount,
                originalSha256,
                redactedSha256,
                isSigned,
                signaturePath,
                null
        );
    }
}
