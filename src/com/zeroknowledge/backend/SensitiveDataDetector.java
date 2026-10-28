package com.zeroknowledge.backend;

import com.zeroknowledge.model.RedactionMatch;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Configurable heuristic sensitive-data detector using regular expressions.
 *
 * <h3>Important Security & Design Notes</h3>
 * <ul>
 *   <li>Regular expressions provide <strong>heuristic candidate detection</strong>, not perfect semantic
 *       personal-information recognition.</li>
 *   <li>All returned {@link RedactionMatch} candidates have {@code selectedForRedaction = false} by default
 *       so that user confirmation is required before redaction is applied.</li>
 *   <li>Raw matched values are never stored in {@link RedactionMatch#toString()}, logs, or exceptions;
 *       only privacy-safe masked previews and character offsets are exposed.</li>
 * </ul>
 */
public final class SensitiveDataDetector {

    /**
     * Defines a single heuristic detection rule.
     */
    public static final class DetectionRule {
        private final String ruleId;
        private final String candidateType;
        private final Pattern pattern;
        private final double confidence;
        private final String replacementToken;

        public DetectionRule(
                String ruleId,
                String candidateType,
                Pattern pattern,
                double confidence,
                String replacementToken) {
            this.ruleId = Objects.requireNonNull(ruleId, "ruleId must not be null");
            this.candidateType = Objects.requireNonNull(candidateType, "candidateType must not be null");
            this.pattern = Objects.requireNonNull(pattern, "pattern must not be null");
            if (confidence < 0.0 || confidence > 1.0) {
                throw new IllegalArgumentException("Confidence must be in [0.0, 1.0]");
            }
            this.confidence = confidence;
            this.replacementToken = Objects.requireNonNull(replacementToken, "replacementToken must not be null");
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
    }

    private final List<DetectionRule> rules;

    /**
     * Creates a detector initialized with standard built-in heuristic rules.
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
     *
     * @param ruleId           unique rule identifier (e.g. "RULE_CUSTOM_EMP_ID")
     * @param candidateType    category label (e.g. "EMPLOYEE_ID")
     * @param regex            Java regular expression pattern
     * @param confidence       heuristic confidence in [0.0, 1.0]
     * @param replacementToken replacement token (e.g. "[REDACTED_EMP_ID]")
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
                    ? "[REDACTED_" + candidateType.trim().toUpperCase() + "]"
                    : replacementToken.trim();
            this.rules.add(new DetectionRule(ruleId.trim(), candidateType.trim().toUpperCase(), compiled, confidence, token));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regular expression for rule " + ruleId + ": " + e.getDescription(), e);
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
        return detectInternal(text, -1, -1, "TXT");
    }

    /**
     * Scans a single CSV cell at {@code (rowIndex, columnIndex)} and returns cell-scoped {@link RedactionMatch} candidates.
     * Candidates default to {@code selectedForRedaction = false} (requiring user approval).
     */
    public List<RedactionMatch> detectInCell(String cellText, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || columnIndex < 0) {
            throw new IllegalArgumentException("CSV rowIndex and columnIndex must be non-negative");
        }
        return detectInternal(cellText, rowIndex, columnIndex, "CSV_R" + rowIndex + "C" + columnIndex);
    }

    private List<RedactionMatch> detectInternal(String text, int rowIndex, int columnIndex, String prefix) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }

        // Deduplicate exact identical spans [start, end) keeping the highest confidence rule
        Map<String, RedactionMatch> uniqueSpanMatches = new LinkedHashMap<>();
        int sequence = 1;

        for (DetectionRule rule : rules) {
            Matcher matcher = rule.getPattern().matcher(text);
            while (matcher.find()) {
                int start = matcher.start();
                int end = matcher.end();
                if (end <= start) {
                    continue;
                }
                String matchedSlice = text.substring(start, end);
                // Skip if slice is already a redaction marker
                if (matchedSlice.startsWith("[REDACTED_") && matchedSlice.endsWith("]")) {
                    continue;
                }

                String spanKey = start + ":" + end;
                RedactionMatch existing = uniqueSpanMatches.get(spanKey);
                if (existing != null && existing.getConfidence() >= rule.getConfidence()) {
                    continue;
                }

                String matchId = prefix + "_M" + (sequence++);
                String masked = RedactionMatch.maskValue(matchedSlice);
                RedactionMatch candidate = new RedactionMatch(
                        matchId,
                        rule.getCandidateType(),
                        rule.getRuleId(),
                        rule.getConfidence(),
                        start,
                        end,
                        rowIndex,
                        columnIndex,
                        masked,
                        rule.getReplacementToken(),
                        false // Never auto-approve without user confirmation
                );
                uniqueSpanMatches.put(spanKey, candidate);
            }
        }

        List<RedactionMatch> result = new ArrayList<>(uniqueSpanMatches.values());
        Collections.sort(result);
        return Collections.unmodifiableList(result);
    }

    private static List<DetectionRule> createDefaultRules() {
        List<DetectionRule> defaults = new ArrayList<>();

        // 1. Email addresses
        defaults.add(new DetectionRule(
                "RULE_EMAIL_STD",
                "EMAIL",
                Pattern.compile("\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,24}\\b"),
                0.95,
                "[REDACTED_EMAIL]"));

        // 2. US / International SSN or National ID (XXX-XX-XXXX)
        defaults.add(new DetectionRule(
                "RULE_SSN_DASHED",
                "SSN",
                Pattern.compile("\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"),
                0.92,
                "[REDACTED_SSN]"));

        // 3. Payment / Credit Card numbers (13-19 digits, with optional spaces or hyphens)
        defaults.add(new DetectionRule(
                "RULE_CREDIT_CARD",
                "CREDIT_CARD",
                Pattern.compile("\\b(?:\\d{4}[ -]?){3}\\d{1,4}\\b"),
                0.88,
                "[REDACTED_CARD]"));

        // 4. Phone numbers (International & North American formats, avoiding simple dates)
        defaults.add(new DetectionRule(
                "RULE_PHONE_INTL",
                "PHONE",
                Pattern.compile("(?<!\\d)(?:\\+\\d{1,3}[ -.]?)?(?:\\(\\d{2,4}\\)[ -.]?|\\d{3}[ -.])\\d{3,4}[ -.]\\d{4}(?!\\d)"),
                0.85,
                "[REDACTED_PHONE]"));

        // 5. Defensible Name Rule: Titled Person Name (e.g., "Mr. John Smith", "Dr. Alice Vance")
        // Using explicit honorifics avoids false-positive matching of arbitrary capitalized nouns.
        defaults.add(new DetectionRule(
                "RULE_TITLED_NAME",
                "PERSON_NAME",
                Pattern.compile("\\b(?:Mr|Mrs|Ms|Mx|Dr|Prof)\\.?\\s+[A-Z][a-z]{1,25}(?:\\s+[A-Z][a-z]{1,25}){0,2}\\b"),
                0.78,
                "[REDACTED_NAME]"));

        // 6. Common Government / Tax / Passport / Employee ID patterns (e.g., ID-12345678, SSN, PAN, etc.)
        defaults.add(new DetectionRule(
                "RULE_GOV_ID",
                "ID_NUMBER",
                Pattern.compile("\\b(?:EMP|ID|PASSPORT|ACCT|PAT)-[A-Z0-9]{4,14}\\b|[A-Z]{5}\\d{4}[A-Z]\\b"),
                0.86,
                "[REDACTED_ID]"));

        return defaults;
    }
}
