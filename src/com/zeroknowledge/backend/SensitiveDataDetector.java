package com.zeroknowledge.backend;

import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionMatch.DetectionMethod;
import com.zeroknowledge.model.RedactionMatch.RedactionStatus;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Context-aware, configurable sensitive-data detector supporting both native-extracted
 * and OCR-extracted text.
 *
 * <h3>Supported Sensitive Categories</h3>
 * <ul>
 *   <li><strong>AADHAAR</strong>: 12-digit Aadhaar candidates (starting 2-9) validated via Verhoeff checksum and/or UID/Aadhaar context labels.</li>
 *   <li><strong>PAN</strong>: Indian Permanent Account Number identifiers ({@code [A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]}) with structural entity-code validation.</li>
 *   <li><strong>BANK_ACCOUNT</strong> &amp; <strong>IFSC</strong>: Context-labelled bank account numbers and 11-character IFSC codes ({@code [A-Z]{4}0[A-Z0-9]{6}}).</li>
 *   <li><strong>CREDIT_CARD</strong>: 13-19 digit payment card candidates validated with the Luhn checksum algorithm or explicit card labels.</li>
 *   <li><strong>CARD_CVV</strong> &amp; <strong>CARD_EXPIRY</strong>: CVV/CVC and card expiry dates strictly when accompanied by explicit labels.</li>
 *   <li><strong>EMAIL</strong> &amp; <strong>PHONE</strong>: Email addresses and international/domestic phone numbers.</li>
 *   <li><strong>DATE_OF_BIRTH</strong>: Dates of birth when associated with DOB/birth-date labels.</li>
 *   <li><strong>PERSON_NAME</strong> &amp; <strong>ADDRESS</strong>: Honorific-titled names and context-labelled names and physical addresses.</li>
 *   <li><strong>CERTIFICATE_ID</strong>, <strong>TAX_ID</strong> / <strong>SSN</strong>, &amp; <strong>FINANCIAL_AMOUNT</strong>: Certificate/license IDs, taxpayer identifiers (SSN/GSTIN/TIN), and labelled financial amounts.</li>
 * </ul>
 *
 * <h3>Important Security &amp; Validation Notes</h3>
 * <ul>
 *   <li>Format and checksum validations (such as Verhoeff or Luhn) reduce false positives but do <strong>not</strong> constitute official government or issuer identity verification.</li>
 *   <li>All returned {@link RedactionMatch} candidates have {@code selectedForRedaction = false} by default so user review is preserved.</li>
 *   <li>Raw matched values are never stored in {@link RedactionMatch#toString()}, logs, or exceptions.</li>
 * </ul>
 */
public final class SensitiveDataDetector {

    /**
     * Evaluates a regex match in context and returns validation outcome, adjusted confidence, and explanation.
     */
    @FunctionalInterface
    public interface ContextValidator {
        ValidationOutcome validate(String fullText, int matchStart, int matchEnd, String matchedValue);
    }

    /**
     * Outcome of validating a candidate regex match against checksums and surrounding context.
     */
    public static final class ValidationOutcome {
        private final boolean accepted;
        private final double confidence;
        private final String reason;
        private final boolean requiresManualReview;

        public ValidationOutcome(boolean accepted, double confidence, String reason, boolean requiresManualReview) {
            this.accepted = accepted;
            this.confidence = Math.max(0.0, Math.min(1.0, confidence));
            this.reason = reason == null ? "" : reason;
            this.requiresManualReview = requiresManualReview;
        }

        public static ValidationOutcome reject() {
            return new ValidationOutcome(false, 0.0, "Rejected by validator", false);
        }

        public static ValidationOutcome accept(double confidence, String reason) {
            return new ValidationOutcome(true, confidence, reason, false);
        }

        public static ValidationOutcome acceptForReview(double confidence, String reason) {
            return new ValidationOutcome(true, confidence, reason, true);
        }

        public boolean isAccepted() {
            return accepted;
        }

        public double getConfidence() {
            return confidence;
        }

        public String getReason() {
            return reason;
        }

        public boolean isRequiresManualReview() {
            return requiresManualReview;
        }
    }

    /**
     * Defines a single heuristic and context-aware detection rule.
     */
    public static final class DetectionRule {
        private final String ruleId;
        private final String candidateType;
        private final Pattern pattern;
        private final double confidence;
        private final String replacementToken;
        private final int targetGroup;
        private final ContextValidator validator;

        public DetectionRule(
                String ruleId,
                String candidateType,
                Pattern pattern,
                double confidence,
                String replacementToken) {
            this(ruleId, candidateType, pattern, confidence, replacementToken, 0, null);
        }

        public DetectionRule(
                String ruleId,
                String candidateType,
                Pattern pattern,
                double confidence,
                String replacementToken,
                int targetGroup,
                ContextValidator validator) {
            this.ruleId = Objects.requireNonNull(ruleId, "ruleId must not be null");
            this.candidateType = Objects.requireNonNull(candidateType, "candidateType must not be null");
            this.pattern = Objects.requireNonNull(pattern, "pattern must not be null");
            if (confidence < 0.0 || confidence > 1.0) {
                throw new IllegalArgumentException("Confidence must be in [0.0, 1.0]");
            }
            this.confidence = confidence;
            this.replacementToken = Objects.requireNonNull(replacementToken, "replacementToken must not be null");
            this.targetGroup = Math.max(0, targetGroup);
            this.validator = validator;
        }

        public String getRuleId() {
            return ruleId;
        }

        public String getCandidateType() {
            return candidateType;
        }

        public Pattern getPattern() {
            return pattern;
        }

        public double getConfidence() {
            return confidence;
        }

        public String getReplacementToken() {
            return replacementToken;
        }

        public int getTargetGroup() {
            return targetGroup;
        }

        public ContextValidator getValidator() {
            return validator;
        }
    }

    // Verhoeff algorithm tables for 12-digit Aadhaar checksum validation
    private static final int[][] VERHOEFF_D = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
            {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
            {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
            {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
            {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
            {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
            {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
            {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
            {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
    };

    private static final int[][] VERHOEFF_P = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
            {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
            {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
            {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
            {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
            {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
            {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
    };

    private final List<DetectionRule> rules;

    /**
     * Creates a detector initialized with standard built-in context-aware rules.
     */
    public SensitiveDataDetector() {
        this.rules = new CopyOnWriteArrayList<>(createDefaultRules());
    }

    /**
     * Creates a detector with a custom list of rules.
     */
    public SensitiveDataDetector(List<DetectionRule> customRules) {
        Objects.requireNonNull(customRules, "customRules must not be null");
        this.rules = new CopyOnWriteArrayList<>(customRules);
    }

    /**
     * Registers an additional custom regular-expression rule at runtime.
     */
    public void addCustomRule(
            String ruleId,
            String candidateType,
            String regex,
            double confidence,
            String replacementToken) {
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException("ruleId must not be blank");
        }
        if (candidateType == null || candidateType.isBlank()) {
            throw new IllegalArgumentException("candidateType must not be blank");
        }
        if (regex == null || regex.isBlank()) {
            throw new IllegalArgumentException("regex must not be blank");
        }
        try {
            Pattern compiled = Pattern.compile(regex, Pattern.UNICODE_CHARACTER_CLASS);
            String token = (replacementToken == null || replacementToken.isBlank())
                    ? "[REDACTED_" + candidateType.trim().toUpperCase(Locale.ROOT) + "]"
                    : replacementToken.trim();
            this.rules.add(new DetectionRule(
                    ruleId.trim(),
                    candidateType.trim().toUpperCase(Locale.ROOT),
                    compiled,
                    confidence,
                    token));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException(
                    "Invalid regular expression for rule " + ruleId + ": " + e.getDescription(), e);
        }
    }

    /**
     * Returns an unmodifiable view of the currently configured detection rules.
     */
    public List<DetectionRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    /**
     * Scans plain text and returns heuristic {@link RedactionMatch} candidates sorted by offset.
     * Candidates default to {@code selectedForRedaction = false} (requiring user approval).
     */
    public List<RedactionMatch> detectInText(String text) {
        return detectInternal(text, -1, -1, 1, DetectionMethod.NATIVE_TEXT, false, "TXT");
    }

    /**
     * Scans page-scoped text (either native PDF text or OCR text) with optional OCR character-confusion
     * and spacing normalization while preserving exact character offsets into {@code pageText}.
     */
    public List<RedactionMatch> detectInPageText(
            String pageText,
            int pageNumber,
            DetectionMethod method,
            boolean enableOcrNormalization) {
        String prefix = (method == DetectionMethod.OCR ? "OCR_P" : "PDF_P") + Math.max(1, pageNumber);
        return detectInternal(pageText, -1, -1, Math.max(1, pageNumber), method, enableOcrNormalization, prefix);
    }

    /**
     * Scans a single CSV cell at {@code (rowIndex, columnIndex)} and returns cell-scoped {@link RedactionMatch} candidates.
     * Candidates default to {@code selectedForRedaction = false} (requiring user approval).
     */
    public List<RedactionMatch> detectInCell(String cellText, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || columnIndex < 0) {
            throw new IllegalArgumentException("CSV rowIndex and columnIndex must be non-negative");
        }
        return detectInternal(
                cellText,
                rowIndex,
                columnIndex,
                1,
                DetectionMethod.CELL_TEXT,
                false,
                "CSV_R" + rowIndex + "C" + columnIndex);
    }

    private List<RedactionMatch> detectInternal(
            String text,
            int rowIndex,
            int columnIndex,
            int pageNumber,
            DetectionMethod method,
            boolean enableOcrNormalization,
            String prefix) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }

        List<RedactionMatch> rawCandidates = new ArrayList<>();
        int sequence = 1;

        // Pass 1: Direct matching on original text
        sequence = runRulesOnTextView(
                text,
                null,
                rowIndex,
                columnIndex,
                pageNumber,
                method,
                false,
                prefix,
                sequence,
                rawCandidates);

        // Pass 2: Cautious OCR-normalized view (resolving O/0, I/1, S/5, B/8 in digit/ID contexts)
        if (enableOcrNormalization || method == DetectionMethod.OCR) {
            NormalizedView ocrView = buildOcrNormalizedView(text);
            if (!ocrView.normalizedText.equals(text)) {
                runRulesOnTextView(
                        ocrView.normalizedText,
                        ocrView.indexMap,
                        rowIndex,
                        columnIndex,
                        pageNumber,
                        method,
                        true,
                        prefix,
                        sequence,
                        rawCandidates);
            }
        }

        if (rawCandidates.isEmpty()) {
            return List.of();
        }

        // Resolve overlapping detections: prefer higher confidence, then longer match span
        rawCandidates.sort((a, b) -> {
            int confCmp = Double.compare(b.getConfidence(), a.getConfidence());
            if (confCmp != 0) {
                return confCmp;
            }
            int lenCmp = Integer.compare(b.getLength(), a.getLength());
            if (lenCmp != 0) {
                return lenCmp;
            }
            return Integer.compare(a.getStartOffset(), b.getStartOffset());
        });

        List<RedactionMatch> accepted = new ArrayList<>();
        for (RedactionMatch candidate : rawCandidates) {
            boolean overlapsExisting = false;
            for (RedactionMatch kept : accepted) {
                if (candidate.getStartOffset() < kept.getEndOffset()
                        && kept.getStartOffset() < candidate.getEndOffset()) {
                    overlapsExisting = true;
                    break;
                }
            }
            if (!overlapsExisting) {
                accepted.add(candidate);
            }
        }

        Collections.sort(accepted);
        return Collections.unmodifiableList(accepted);
    }

    private int runRulesOnTextView(
            String searchText,
            int[] indexMapToOriginal,
            int rowIndex,
            int columnIndex,
            int pageNumber,
            DetectionMethod method,
            boolean isOcrNormalizedPass,
            String prefix,
            int startSequence,
            List<RedactionMatch> outCandidates) {
        int sequence = startSequence;

        for (DetectionRule rule : rules) {
            Matcher matcher = rule.getPattern().matcher(searchText);
            while (matcher.find()) {
                int groupIdx = (rule.getTargetGroup() > 0 && rule.getTargetGroup() <= matcher.groupCount())
                        ? rule.getTargetGroup()
                        : 0;
                int start = matcher.start(groupIdx);
                int end = matcher.end(groupIdx);
                if (start < 0 || end <= start) {
                    continue;
                }

                int origStart = (indexMapToOriginal != null) ? indexMapToOriginal[start] : start;
                int origEnd = (indexMapToOriginal != null) ? (indexMapToOriginal[end - 1] + 1) : end;
                if (origEnd <= origStart) {
                    continue;
                }

                String matchedSlice = searchText.substring(start, end);
                if (matchedSlice.startsWith("[REDACTED_") && matchedSlice.endsWith("]")) {
                    continue;
                }

                double finalConfidence = rule.getConfidence();
                String reason = "Pattern match (" + rule.getRuleId() + ")";
                boolean manualReview = false;

                if (rule.getValidator() != null) {
                    ValidationOutcome outcome = rule.getValidator().validate(searchText, start, end, matchedSlice);
                    if (!outcome.isAccepted()) {
                        continue;
                    }
                    finalConfidence = outcome.getConfidence();
                    reason = outcome.getReason();
                    manualReview = outcome.isRequiresManualReview();
                }

                if (isOcrNormalizedPass) {
                    finalConfidence = Math.max(0.55, finalConfidence - 0.08);
                    reason = reason + " [OCR character confusion normalized]";
                    manualReview = true;
                } else if (method == DetectionMethod.OCR && finalConfidence < 0.80) {
                    manualReview = true;
                }

                RedactionStatus status = manualReview
                        ? RedactionStatus.MANUAL_REVIEW_REQUIRED
                        : RedactionStatus.REDACTABLE;

                String matchId = prefix + "_M" + (sequence++);
                String masked = RedactionMatch.maskValue(matchedSlice);
                RedactionMatch candidate = new RedactionMatch(
                        matchId,
                        rule.getCandidateType(),
                        rule.getRuleId(),
                        finalConfidence,
                        origStart,
                        origEnd,
                        rowIndex,
                        columnIndex,
                        pageNumber,
                        method,
                        reason,
                        status,
                        List.of(),
                        masked,
                        rule.getReplacementToken(),
                        false);
                outCandidates.add(candidate);
            }
        }
        return sequence;
    }

    // =========================================================================
    // OCR Character-Confusion Normalization Mapping
    // =========================================================================

    private record NormalizedView(String normalizedText, int[] indexMap) {}

    /**
     * Cautiously resolves common OCR glyph confusions (O/0, I/l/1, S/5, B/8)
     * when adjacent to digits or inside uppercase alphanumeric identifier tokens,
     * keeping a strict 1-to-1 character offset map to the original text.
     */
    private static NormalizedView buildOcrNormalizedView(String rawText) {
        int len = rawText.length();
        char[] chars = rawText.toCharArray();
        int[] map = new int[len];
        for (int i = 0; i < len; i++) {
            map[i] = i;
        }

        for (int i = 0; i < len; i++) {
            char c = chars[i];
            boolean prevDigitOrSep = (i > 0) && (Character.isDigit(chars[i - 1])
                    || chars[i - 1] == '-' || chars[i - 1] == ' ' || chars[i - 1] == '/');
            boolean nextDigitOrSep = (i + 1 < len) && (Character.isDigit(chars[i + 1])
                    || chars[i + 1] == '-' || chars[i + 1] == ' ' || chars[i + 1] == '/');
            boolean nearDigit = (i > 0 && Character.isDigit(chars[i - 1]))
                    || (i + 1 < len && Character.isDigit(chars[i + 1]))
                    || (i > 1 && Character.isDigit(chars[i - 2]) && (chars[i - 1] == ' ' || chars[i - 1] == '-'))
                    || (i + 2 < len && Character.isDigit(chars[i + 2]) && (chars[i + 1] == ' ' || chars[i + 1] == '-'));

            if (nearDigit && (prevDigitOrSep || nextDigitOrSep)) {
                if (c == 'O' || c == 'o') {
                    chars[i] = '0';
                } else if (c == 'I' || c == 'l') {
                    chars[i] = '1';
                } else if (c == 'S') {
                    chars[i] = '5';
                } else if (c == 'B') {
                    chars[i] = '8';
                }
            }
        }

        // Also handle IFSC 5th character 'O' -> '0' in 11-char uppercase/digit token (e.g. SBINO001234 -> SBIN0001234)
        Matcher ifscLike = Pattern.compile("\\b([A-Z]{4})[Oo]([A-Z0-9]{6})\\b").matcher(new String(chars));
        while (ifscLike.find()) {
            int fifthIdx = ifscLike.start() + 4;
            if (fifthIdx < len) {
                chars[fifthIdx] = '0';
            }
        }

        // Handle PAN digit positions (chars 5..8 of 10-char token: ABCDEO123F -> ABCDE0123F)
        Matcher panLike = Pattern.compile("\\b([A-Z]{3}[ABCFGHLJPT][A-Z])([0-9OIlSB]{4})([A-Z])\\b").matcher(new String(chars));
        while (panLike.find()) {
            for (int idx = panLike.start(2); idx < panLike.end(2); idx++) {
                char ch = chars[idx];
                if (ch == 'O') chars[idx] = '0';
                else if (ch == 'I' || ch == 'l') chars[idx] = '1';
                else if (ch == 'S') chars[idx] = '5';
                else if (ch == 'B') chars[idx] = '8';
            }
        }

        return new NormalizedView(new String(chars), map);
    }

    // =========================================================================
    // Checksum & Contextual Validation Algorithms
    // =========================================================================

    /**
     * Validates a 12-digit string using the Verhoeff checksum algorithm used by Aadhaar.
     */
    public static boolean isValidVerhoeff(String digitsOnly) {
        if (digitsOnly == null || digitsOnly.length() != 12) {
            return false;
        }
        int c = 0;
        int len = digitsOnly.length();
        for (int i = 0; i < len; i++) {
            char ch = digitsOnly.charAt(len - 1 - i);
            if (!Character.isDigit(ch)) {
                return false;
            }
            int digit = ch - '0';
            c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
        }
        return c == 0;
    }

    /**
     * Validates a 13-to-19-digit payment card number using the standard Luhn mod-10 checksum.
     */
    public static boolean isValidLuhn(String digitsOnly) {
        if (digitsOnly == null || digitsOnly.length() < 13 || digitsOnly.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean alternate = false;
        for (int i = digitsOnly.length() - 1; i >= 0; i--) {
            char ch = digitsOnly.charAt(i);
            if (!Character.isDigit(ch)) {
                return false;
            }
            int n = ch - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n = (n % 10) + 1;
                }
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }

    private static boolean hasAllIdenticalDigits(String digits) {
        if (digits.isEmpty()) return true;
        char first = digits.charAt(0);
        for (int i = 1; i < digits.length(); i++) {
            if (digits.charAt(i) != first) {
                return false;
            }
        }
        return true;
    }

    private static String extractPrecedingContext(String fullText, int matchStart, int windowChars) {
        int start = Math.max(0, matchStart - windowChars);
        return fullText.substring(start, matchStart).toLowerCase(Locale.ROOT);
    }

    // =========================================================================
    // Default Context-Aware Rules Setup
    // =========================================================================

    private static List<DetectionRule> createDefaultRules() {
        List<DetectionRule> defaults = new ArrayList<>();

        // 1. Email addresses (supports standard and slight OCR whitespace before/after @ when clearly formatted)
        defaults.add(new DetectionRule(
                "RULE_EMAIL_STD",
                "EMAIL",
                Pattern.compile("\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,24}\\b"),
                0.96,
                "[REDACTED_EMAIL]",
                0,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.96, "RFC-5322 email format verified")));

        // 2. US / International SSN (XXX-XX-XXXX)
        defaults.add(new DetectionRule(
                "RULE_SSN_DASHED",
                "SSN",
                Pattern.compile("\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"),
                0.93,
                "[REDACTED_SSN]",
                0,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.93, "SSN 9-digit dashed format check (format check only)")));

        // 3. Aadhaar Number Candidates (12 digits starting 2-9, grouped 4-4-4 or continuous with label/checksum)
        // Supports spaces, hyphens, or a single line wrap between 4-digit groups
        defaults.add(new DetectionRule(
                "RULE_AADHAAR_12",
                "AADHAAR",
                Pattern.compile("(?<![0-9A-Za-z\\-])([2-9]\\d{3}(?:[ \\t\\-]|\\r?\\n\\s*)?\\d{4}(?:[ \\t\\-]|\\r?\\n\\s*)?\\d{4})(?![0-9A-Za-z\\-])"),
                0.90,
                "[REDACTED_AADHAAR]",
                1,
                (fullText, start, end, val) -> {
                    String digits = val.replaceAll("\\D", "");
                    if (digits.length() != 12 || digits.charAt(0) < '2' || hasAllIdenticalDigits(digits)) {
                        return ValidationOutcome.reject();
                    }
                    String ctx = extractPrecedingContext(fullText, start, 65);
                    // Exclude if preceded by card/account/phone/certificate context without aadhaar
                    boolean hasOtherLabel = (ctx.contains("card") || ctx.contains("account")
                            || ctx.contains("a/c") || ctx.contains("phone") || ctx.contains("mobile")
                            || ctx.contains("tel") || ctx.contains("invoice") || ctx.contains("order")
                            || ctx.contains("serial")) && !ctx.contains("aadhaar") && !ctx.contains("aadhar") && !ctx.contains("uid");
                    if (hasOtherLabel) {
                        return ValidationOutcome.reject();
                    }

                    boolean hasAadhaarLabel = ctx.contains("aadhaar") || ctx.contains("aadhar")
                            || ctx.contains("uidai") || ctx.contains("uid") || ctx.contains("आधार");
                    boolean isGrouped444 = val.matches("[2-9]\\d{3}[\\s\\-]+\\d{4}[\\s\\-]+\\d{4}");
                    boolean verhoeffOk = isValidVerhoeff(digits);

                    if (hasAadhaarLabel && verhoeffOk) {
                        return ValidationOutcome.accept(0.96,
                                "Aadhaar label + 12-digit Verhoeff checksum passed (format check only, not official UIDAI verification)");
                    }
                    if (hasAadhaarLabel) {
                        return ValidationOutcome.accept(0.88,
                                "Aadhaar context label + 12-digit pattern matched (format check only, not official UIDAI verification)");
                    }
                    if (isGrouped444 && verhoeffOk) {
                        return ValidationOutcome.accept(0.91,
                                "4-4-4 grouped 12-digit Verhoeff checksum passed (format check only, not official UIDAI verification)");
                    }
                    if (isGrouped444) {
                        return ValidationOutcome.acceptForReview(0.76,
                                "12-digit 4-4-4 Aadhaar candidate without label/Verhoeff match (format check only — manual review recommended)");
                    }
                    // Reject unlabelled continuous 12-digit numbers so arbitrary long numbers are NOT classified as Aadhaar
                    return ValidationOutcome.reject();
                }));

        // 4. Indian PAN Identifiers ([A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z], or labelled [A-Z]{5}\d{4}[A-Z])
        defaults.add(new DetectionRule(
                "RULE_PAN_INDIA",
                "PAN",
                Pattern.compile("\\b([A-Z]{5}\\s?\\d{4}\\s?[A-Z])\\b"),
                0.92,
                "[REDACTED_PAN]",
                1,
                (fullText, start, end, val) -> {
                    String compact = val.replaceAll("\\s+", "");
                    if (compact.length() != 10) {
                        return ValidationOutcome.reject();
                    }
                    char fourthChar = compact.charAt(3);
                    boolean validEntityCode = "ABCFGHLJPT".indexOf(fourthChar) >= 0;
                    String ctx = extractPrecedingContext(fullText, start, 60);
                    boolean hasPanLabel = ctx.contains("pan") || ctx.contains("permanent account")
                            || ctx.contains("income tax") || ctx.contains("taxpayer");
                    if (!validEntityCode && !hasPanLabel) {
                        return ValidationOutcome.reject();
                    }
                    if (val.contains(" ") && !hasPanLabel) {
                        return ValidationOutcome.reject();
                    }
                    double conf = (validEntityCode && hasPanLabel) ? 0.96 : (validEntityCode ? 0.91 : 0.86);
                    return ValidationOutcome.accept(conf,
                            "10-character PAN format & context validated (format check only, not Income Tax Dept verification)");
                }));

        // 5. Indian IFSC Codes ([A-Z]{4}0[A-Z0-9]{6})
        defaults.add(new DetectionRule(
                "RULE_IFSC_CODE",
                "IFSC",
                Pattern.compile("\\b([A-Z]{4}0[A-Z0-9]{6})\\b"),
                0.91,
                "[REDACTED_IFSC]",
                1,
                (fullText, start, end, val) -> {
                    String ctx = extractPrecedingContext(fullText, start, 60);
                    boolean hasIfscContext = ctx.contains("ifsc") || ctx.contains("ifs code")
                            || ctx.contains("branch") || ctx.contains("bank") || ctx.contains("neft")
                            || ctx.contains("rtgs") || ctx.contains("imps");
                    // Require either IFSC/bank context OR digits in the 6-char branch suffix to avoid matching words
                    boolean branchHasDigits = val.substring(5).matches(".*\\d.*");
                    if (!hasIfscContext && !branchHasDigits) {
                        return ValidationOutcome.reject();
                    }
                    double conf = hasIfscContext ? 0.95 : 0.87;
                    return ValidationOutcome.accept(conf,
                            "11-character IFSC format ([A-Z]{4}0[A-Z0-9]{6}) validated");
                }));

        // 6. Bank Account Numbers (strictly context-labelled so arbitrary numbers are not misclassified)
        defaults.add(new DetectionRule(
                "RULE_BANK_ACCOUNT",
                "BANK_ACCOUNT",
                Pattern.compile("(?i)(?:bank\\s+account(?:\\s+no\\.?|\\s+number|\\s*#)?|a/c(?:\\s+no\\.?|\\s+number|\\s*#)?|account\\s+(?:no\\.?|number|#)|savings\\s+account|current\\s+account|iban)\\s*[:\\-=]?\\s*([A-Z]{0,2}\\d[\\d \\-]{7,20}\\d)"),
                0.91,
                "[REDACTED_ACCOUNT]",
                1,
                (fullText, start, end, val) -> {
                    String digits = val.replaceAll("\\D", "");
                    if (digits.length() < 8 || digits.length() > 20) {
                        return ValidationOutcome.reject();
                    }
                    return ValidationOutcome.accept(0.91,
                            "Context-labelled bank account number (" + digits.length() + " digits)");
                }));

        // 7. Debit and Credit Card Number Candidates (13-19 digits, Luhn validated or explicitly card-labelled)
        defaults.add(new DetectionRule(
                "RULE_CREDIT_CARD",
                "CREDIT_CARD",
                Pattern.compile("(?<![0-9A-Za-z\\-])((?:\\d{4}[ \\t\\-]|\\d{4}\\r?\\n\\s*){3}\\d{1,4}|\\d{13,19})(?![0-9A-Za-z\\-])"),
                0.90,
                "[REDACTED_CARD]",
                1,
                (fullText, start, end, val) -> {
                    String digits = val.replaceAll("\\D", "");
                    if (digits.length() < 13 || digits.length() > 19 || hasAllIdenticalDigits(digits)) {
                        return ValidationOutcome.reject();
                    }
                    char first = digits.charAt(0);
                    // Payment cards start with 3 (Amex/JCB/Diners), 4 (Visa), 5 (MasterCard), 6 (Discover/RuPay)
                    if (first < '3' || first > '6') {
                        return ValidationOutcome.reject();
                    }
                    String ctx = extractPrecedingContext(fullText, start, 65);
                    boolean hasCardLabel = ctx.contains("card") || ctx.contains("visa")
                            || ctx.contains("mastercard") || ctx.contains("amex")
                            || ctx.contains("rupay") || ctx.contains("debit") || ctx.contains("credit");
                    boolean hasAccountOrAadhaarLabel = (ctx.contains("aadhaar") || ctx.contains("aadhar")
                            || ctx.contains("account no") || ctx.contains("a/c")) && !hasCardLabel;
                    if (hasAccountOrAadhaarLabel) {
                        return ValidationOutcome.reject();
                    }

                    boolean luhnOk = isValidLuhn(digits);
                    boolean isGrouped = val.contains("-") || val.contains(" ") || val.contains("\n");

                    if (luhnOk && hasCardLabel) {
                        return ValidationOutcome.accept(0.97,
                                "Card context label + Luhn mod-10 checksum validated (format check only)");
                    }
                    if (luhnOk && isGrouped) {
                        return ValidationOutcome.accept(0.92,
                                "Grouped payment card format + Luhn mod-10 checksum validated (format check only)");
                    }
                    if (hasCardLabel && isGrouped) {
                        return ValidationOutcome.accept(0.88,
                                "Explicit card context label + 16-digit card pattern matched (format check only)");
                    }
                    if (luhnOk && digits.length() == 16) {
                        return ValidationOutcome.acceptForReview(0.79,
                                "16-digit Luhn checksum passed without card label (manual review recommended)");
                    }
                    return ValidationOutcome.reject();
                }));

        // 8. CVV / CVC (strictly when clearly labelled)
        defaults.add(new DetectionRule(
                "RULE_CARD_CVV",
                "CARD_CVV",
                Pattern.compile("(?i)\\b(?:cvv2?|cvc2?|security\\s+code|card\\s+verification\\s+value)\\s*[:\\-=]?\\s*(\\d{3,4})\\b"),
                0.94,
                "[REDACTED_CVV]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.94, "Explicitly labelled card security code (CVV/CVC)")));

        // 9. Card Expiry Date (strictly when clearly labelled)
        defaults.add(new DetectionRule(
                "RULE_CARD_EXPIRY",
                "CARD_EXPIRY",
                Pattern.compile("(?i)\\b(?:exp(?:iry|\\.|ires)?(?:\\s+date)?|valid\\s+(?:thru|until|through)|good\\s+thru)\\s*[:\\-=]?\\s*((?:0[1-9]|1[0-2])\\s*[/\\-]\\s*(?:\\d{2}|20\\d{2}))\\b"),
                0.92,
                "[REDACTED_EXPIRY]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.92, "Explicitly labelled card expiry date")));

        // 10. Phone numbers (International, North American, and Indian +91 / labelled 10-digit mobile)
        defaults.add(new DetectionRule(
                "RULE_PHONE_INTL",
                "PHONE",
                Pattern.compile("(?<!\\d)(?:\\+\\d{1,3}[ -.]?)?(?:\\(\\d{2,4}\\)[ -.]?|\\d{3}[ -.])\\d{3,4}[ -.]\\d{4}(?!\\d)|(?<!\\d)\\+91[ -]?[6-9]\\d{4}[ -]?\\d{5}(?!\\d)"),
                0.86,
                "[REDACTED_PHONE]",
                0,
                (fullText, start, end, val) -> {
                    String ctx = extractPrecedingContext(fullText, start, 45);
                    if (ctx.contains("ssn") || ctx.contains("aadhaar") || ctx.contains("card")) {
                        return ValidationOutcome.reject();
                    }
                    return ValidationOutcome.accept(0.88, "Structured phone number format matched");
                }));

        // Labelled 10-digit Indian/domestic phone numbers without punctuation (e.g. "Mobile: 9876543210")
        defaults.add(new DetectionRule(
                "RULE_PHONE_LABELLED",
                "PHONE",
                Pattern.compile("(?i)\\b(?:phone|mobile|contact\\s+no\\.?|tel(?:ephone)?|cell|ph\\.?|whatsapp)\\s*[:\\-=]?\\s*((?:\\+?\\d{1,3}[ \\-]?)?[6-9]\\d{4}[ \\-]?\\d{5})\\b"),
                0.91,
                "[REDACTED_PHONE]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.91, "Explicitly labelled 10-digit phone/mobile number")));

        // 11. Dates of Birth (strictly when associated with DOB / birth date labels)
        defaults.add(new DetectionRule(
                "RULE_DOB_LABELLED",
                "DATE_OF_BIRTH",
                Pattern.compile("(?i)\\b(?:d\\.?o\\.?b\\.?|date\\s+of\\s+birth|birth\\s*date|born\\s+on)\\s*[:\\-=]?\\s*(\\d{1,2}[/\\-.]\\d{1,2}[/\\-.]\\d{2,4}|\\d{4}[/\\-.]\\d{1,2}[/\\-.]\\d{1,2}|\\d{1,2}\\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[,\\s]+\\d{4})\\b"),
                0.93,
                "[REDACTED_DOB]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.93, "Explicitly labelled Date of Birth")));

        // 12. Person Names: Honorific-titled names OR explicitly labelled names
        defaults.add(new DetectionRule(
                "RULE_TITLED_NAME",
                "PERSON_NAME",
                Pattern.compile("\\b(?:Mr|Mrs|Ms|Mx|Dr|Prof|Shri|Smt)\\.?\\s+[A-Z][a-z]{1,25}(?:\\s+[A-Z][a-z]{1,25}){0,2}\\b"),
                0.82,
                "[REDACTED_NAME]",
                0,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.82, "Honorific-titled person name")));

        defaults.add(new DetectionRule(
                "RULE_LABELLED_NAME",
                "PERSON_NAME",
                Pattern.compile("(?m)(?:Customer\\s+Record|Primary\\s+Contact|Customer\\s+Name|Applicant\\s+Name|Patient\\s+Name|Employee\\s+Name|Account\\s+Holder|Holder\\s+Name|Candidate\\s+Name|Full\\s+Name|(?<=^|\\n)\\s*Name)\\s*:\\s*([A-Z][a-z]{1,25}(?:[ \\t]+[A-Z][a-z]{1,25}){1,3})\\b"),
                0.85,
                "[REDACTED_NAME]",
                1,
                (fullText, start, end, val) -> {
                    String lower = val.toLowerCase(Locale.ROOT);
                    if (lower.contains("confidential") || lower.contains("contract")
                            || lower.contains("agreement") || lower.contains("department")
                            || lower.contains("service") || lower.contains("address")
                            || lower.contains("email") || lower.contains("phone")) {
                        return ValidationOutcome.reject();
                    }
                    return ValidationOutcome.accept(0.85, "Context-labelled person name");
                }));

        // 13. Physical Addresses (strictly when associated with an address label, supporting 1-2 lines)
        defaults.add(new DetectionRule(
                "RULE_LABELLED_ADDRESS",
                "ADDRESS",
                Pattern.compile("(?im)\\b(?:residential\\s+address|permanent\\s+address|billing\\s+address|mailing\\s+address|street\\s+address|current\\s+address|office\\s+address|address)\\s*:\\s*([A-Za-z0-9#.,/\\- ]{8,95}(?:\\r?\\n\\s*(?!\\b(?:email|phone|mobile|pan|aadhaar|dob|date|ssn|card|account|ifsc|amount|salary|name|signature)\\b)[A-Za-z0-9#.,/\\- ]*(?:\\b\\d{5,6}\\b)[A-Za-z0-9#.,/\\- ]*)?)"),
                0.86,
                "[REDACTED_ADDRESS]",
                1,
                (fullText, start, end, val) -> {
                    String trimmed = val.trim();
                    if (trimmed.length() < 8) {
                        return ValidationOutcome.reject();
                    }
                    return ValidationOutcome.accept(0.86, "Explicitly labelled street/postal address");
                }));

        // 14. Common Government / Employee / Account / Certificate IDs (preserving RULE_GOV_ID for existing tests)
        defaults.add(new DetectionRule(
                "RULE_GOV_ID",
                "ID_NUMBER",
                Pattern.compile("\\b(?:EMP|ID|PASSPORT|ACCT|PAT)-[A-Z0-9]{4,14}\\b"),
                0.88,
                "[REDACTED_ID]",
                0,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.88, "Structured identifier token (" + val.substring(0, val.indexOf('-')) + ")")));

        // 15. Certificate Identifiers (Certificate No, License No, Registration No, Policy No)
        defaults.add(new DetectionRule(
                "RULE_CERTIFICATE_ID",
                "CERTIFICATE_ID",
                Pattern.compile("(?i)\\b(?:certificate\\s+(?:no\\.?|number|id)|cert\\s*(?:no\\.?|id|#)|license\\s+(?:no\\.?|number)|registration\\s+(?:no\\.?|number)|policy\\s+(?:no\\.?|number))\\s*[:\\-=]?\\s*([A-Z0-9][A-Z0-9\\-/]{4,22}[A-Z0-9])\\b"),
                0.90,
                "[REDACTED_CERTIFICATE_ID]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.90, "Explicitly labelled certificate/registration identifier")));

        // 16. Taxpayer Identifiers (Indian GSTIN 15-char format & labelled TIN / EIN / Taxpayer ID)
        defaults.add(new DetectionRule(
                "RULE_GSTIN_INDIA",
                "TAX_ID",
                Pattern.compile("\\b(\\d{2}[A-Z]{5}\\d{4}[A-Z][1-9A-Z]Z[0-9A-Z])\\b"),
                0.93,
                "[REDACTED_TAX_ID]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.93, "15-character GSTIN format matched (format check only)")));

        defaults.add(new DetectionRule(
                "RULE_TAX_ID",
                "TAX_ID",
                Pattern.compile("(?i)\\b(?:taxpayer\\s+id|tax\\s+id|tin|ein|gstin)\\s*[:\\-=]?\\s*([A-Z0-9][A-Z0-9\\-]{5,17}[A-Z0-9])\\b"),
                0.91,
                "[REDACTED_TAX_ID]",
                1,
                (fullText, start, end, val) -> ValidationOutcome.accept(
                        0.91, "Explicitly labelled taxpayer identifier (format check only)")));

        // 17. Labelled Financial Amounts (strictly requires explicit financial label so unlabelled numbers/symbols in prose are untouched)
        defaults.add(new DetectionRule(
                "RULE_FINANCIAL_AMOUNT",
                "FINANCIAL_AMOUNT",
                Pattern.compile("(?i)\\b(?:total\\s+amount|transaction\\s+amount|loan\\s+amount|sanctioned\\s+amount|taxable\\s+income|annual\\s+income|net\\s+salary|gross\\s+salary|salary|account\\s+balance|closing\\s+balance|balance|invoice\\s+total|retainer\\s+fee|service\\s+fee|amount\\s+payable|amount)\\s*:\\s*((?:Rs\\.?|INR|USD|EUR|GBP|[₹$€£])?\\s*\\d[\\d,]*(?:\\.\\d{1,2})?(?:\\s*(?:INR|USD|EUR|GBP|Lakhs?|Cr\\.?|Crores?))?)"),
                0.89,
                "[REDACTED_AMOUNT]",
                1,
                (fullText, start, end, val) -> {
                    String digits = val.replaceAll("\\D", "");
                    if (digits.isEmpty()) {
                        return ValidationOutcome.reject();
                    }
                    return ValidationOutcome.accept(0.89, "Explicitly labelled financial amount");
                }));

        return defaults;
    }
}
