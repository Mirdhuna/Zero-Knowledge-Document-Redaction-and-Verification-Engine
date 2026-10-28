package com.zeroknowledge.document;

import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Strategy interface for format-specific document scanning and redaction.
 *
 * <p>Also provides shared, verified interval-merging and reverse-order offset replacement
 * utilities so that overlapping and adjacent matches never corrupt character offsets.
 */
public interface DocumentHandler extends DocumentReader {

    /**
     * Scans the document at {@code sourcePath} and returns candidate {@link RedactionMatch} items
     * requiring user confirmation before redaction.
     *
     * @param sourcePath path to the document to scan
     * @param detector   configured sensitive-data detector
     * @return unmodifiable list of detected candidates
     * @throws DocumentProcessingException if the file cannot be read, is malformed, or does not support scanning
     */
    List<RedactionMatch> scan(Path sourcePath, SensitiveDataDetector detector) throws DocumentProcessingException;

    /**
     * Applies user-approved {@link RedactionMatch} items to {@code sourcePath} and writes the redacted
     * output to {@code outputPath} (never overwriting {@code sourcePath}).
     *
     * @param sourcePath      original source document
     * @param outputPath      target output path (must be distinct from {@code sourcePath})
     * @param approvedMatches list of matches (only those with {@code isSelectedForRedaction() == true} are applied)
     * @return structured {@link RedactionResult}
     * @throws DocumentProcessingException if reading or parsing the source document fails
     * @throws RedactionException          if offset validation, redaction, or output writing fails
     */
    RedactionResult applyRedactions(
            Path sourcePath,
            Path outputPath,
            List<RedactionMatch> approvedMatches) throws DocumentProcessingException, RedactionException;

    /**
     * Applies approved non-cell-scoped (or single-cell-scoped) matches to a target string safely.
     *
     * <h3>Offset Integrity & Overlap Resolution</h3>
     * <ol>
     *   <li>Filters only matches where {@code isSelectedForRedaction()} is {@code true}.</li>
     *   <li>Validates that every match lies within {@code [0, sourceText.length()]}.</li>
     *   <li>Sorts matches by {@code startOffset} ascending, then {@code endOffset} descending.</li>
     *   <li>Resolves overlapping ranges by merging overlapping spans into a single span using the primary
     *       match's replacement token (or compound token if distinct types overlap), while keeping adjacent
     *       non-overlapping spans separate so each adjacent candidate gets its own marker.</li>
     *   <li>Applies replacements in reverse order (from highest offset to lowest) so earlier replacements
     *       never shift the character offsets of remaining replacements.</li>
     * </ol>
     */
    static ResolvedRedaction applyMatchesToText(String sourceText, List<RedactionMatch> matches)
            throws RedactionException {
        Objects.requireNonNull(sourceText, "sourceText must not be null");
        if (matches == null || matches.isEmpty()) {
            return new ResolvedRedaction(sourceText, List.of());
        }

        int textLength = sourceText.length();
        List<RedactionMatch> selected = new ArrayList<>();
        for (RedactionMatch match : matches) {
            if (match != null && match.isSelectedForRedaction()) {
                if (match.getStartOffset() < 0 || match.getEndOffset() > textLength
                        || match.getStartOffset() >= match.getEndOffset()) {
                    throw new RedactionException(
                            "Invalid match offset range [" + match.getStartOffset() + ", " + match.getEndOffset()
                                    + ") for text of length " + textLength);
                }
                selected.add(match);
            }
        }

        if (selected.isEmpty()) {
            return new ResolvedRedaction(sourceText, List.of());
        }

        // Sort by startOffset ASC, then endOffset DESC (longest span first at same start)
        selected.sort(Comparator
                .comparingInt(RedactionMatch::getStartOffset)
                .thenComparing(Comparator.comparingInt(RedactionMatch::getEndOffset).reversed()));

        // Resolve overlapping spans (note: adjacent spans where next.start == current.end do NOT overlap)
        List<RedactionMatch> nonOverlapping = new ArrayList<>();
        RedactionMatch current = selected.get(0);

        for (int i = 1; i < selected.size(); i++) {
            RedactionMatch next = selected.get(i);
            if (next.getStartOffset() < current.getEndOffset()) {
                // Overlapping match: merge interval [current.start, max(current.end, next.end))
                int mergedEnd = Math.max(current.getEndOffset(), next.getEndOffset());
                String mergedType = current.getCandidateType().equals(next.getCandidateType())
                        ? current.getCandidateType()
                        : current.getCandidateType() + "+" + next.getCandidateType();
                String mergedToken = current.getReplacementToken().equals(next.getReplacementToken())
                        ? current.getReplacementToken()
                        : current.getReplacementToken();
                current = new RedactionMatch(
                        current.getMatchId() + "_" + next.getMatchId(),
                        mergedType,
                        current.getRuleId(),
                        Math.max(current.getConfidence(), next.getConfidence()),
                        current.getStartOffset(),
                        mergedEnd,
                        current.getRowIndex(),
                        current.getColumnIndex(),
                        current.getMaskedPreview(),
                        mergedToken,
                        true);
            } else {
                // Disjoint or strictly adjacent (next.startOffset >= current.endOffset)
                nonOverlapping.add(current);
                current = next;
            }
        }
        nonOverlapping.add(current);

        // Apply replacements from right to left (descending startOffset) to preserve all earlier offsets
        StringBuilder builder = new StringBuilder(sourceText);
        for (int i = nonOverlapping.size() - 1; i >= 0; i--) {
            RedactionMatch m = nonOverlapping.get(i);
            builder.replace(m.getStartOffset(), m.getEndOffset(), m.getReplacementToken());
        }

        return new ResolvedRedaction(builder.toString(), List.copyOf(nonOverlapping));
    }

    /**
     * Value object holding the transformed text and the resolved list of applied matches.
     */
    final class ResolvedRedaction {
        private final String redactedText;
        private final List<RedactionMatch> appliedMatches;

        public ResolvedRedaction(String redactedText, List<RedactionMatch> appliedMatches) {
            this.redactedText = Objects.requireNonNull(redactedText);
            this.appliedMatches = Objects.requireNonNull(appliedMatches);
        }

        public String getRedactedText() {
            return redactedText;
        }

        public List<RedactionMatch> getAppliedMatches() {
            return appliedMatches;
        }
    }
}
