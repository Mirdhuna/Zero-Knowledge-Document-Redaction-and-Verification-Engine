package com.zeroknowledge.model;

/**
 * Represents a sensitive data match detected within a document.
 */
public class RedactionMatch {
    private final String id;
    private final String candidateType;
    private final String rawValue;
    private final String maskedPreview;
    private final int startOffset;
    private final int endOffset;
    private final int lineNumber;
    private final int columnNumber;
    private final String ruleDescription;
    private boolean selected;

    public RedactionMatch(String id, String candidateType, String rawValue, String maskedPreview,
                          int startOffset, int endOffset, int lineNumber, int columnNumber,
                          String ruleDescription) {
        this.id = id;
        this.candidateType = candidateType;
        this.rawValue = rawValue;
        this.maskedPreview = maskedPreview;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
        this.lineNumber = lineNumber;
        this.columnNumber = columnNumber;
        this.ruleDescription = ruleDescription;
        this.selected = true; // Selected by default for user review
    }

    public String getId() {
        return id;
    }

    public String getCandidateType() {
        return candidateType;
    }

    public String getRawValue() {
        return rawValue;
    }

    public String getMaskedPreview() {
        return maskedPreview;
    }

    public int getStartOffset() {
        return startOffset;
    }

    public int getEndOffset() {
        return endOffset;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public int getColumnNumber() {
        return columnNumber;
    }

    public String getRuleDescription() {
        return ruleDescription;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    public String getLocationDisplay() {
        if (lineNumber > 0 && columnNumber > 0) {
            return "Line " + lineNumber + ", Col " + columnNumber;
        } else if (lineNumber > 0) {
            return "Line " + lineNumber;
        } else if (startOffset >= 0) {
            return "Offset " + startOffset + "-" + endOffset;
        }
        return "Unknown";
    }

    @Override
    public String toString() {
        return "RedactionMatch{" +
                "type='" + candidateType + '\'' +
                ", masked='" + maskedPreview + '\'' +
                ", loc=" + getLocationDisplay() +
                ", selected=" + selected +
                '}';
    }
}
