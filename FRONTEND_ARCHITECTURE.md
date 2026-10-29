# Frontend Architecture & Technical Design Document
## Zero-Knowledge Document Redaction & Verification Engine

### 1. Executive Summary

The **Zero-Knowledge Document Redaction & Verification Engine** desktop application is developed in **Java 21**, **AWT**, and **Swing**. It provides an end-to-end, local-only workflow for:
- Page-by-page native PDF text extraction and local Tesseract OCR on scanned/hybrid PDFs.
- Image preprocessing (resolution upscaling, grayscale conversion, contrast stretching, impulse denoising, deskewing, and Otsu thresholding).
- Context-aware sensitive entity detection (Aadhaar, PAN, IFSC, Bank Account, Credit/Debit Card, labelled CVV/Expiry, Email, Phone, DOB, Name, Address, Certificate ID, Tax ID/GSTIN, and labelled Financial Amounts).
- Exact coordinate mapping (`PdfBoundingBox`) for both native PDF text operators (`Tm`, `Td`, `TD`, `T*`, `cm`, `/Rotate`) and OCR word bounding boxes.
- Permanent native PDF stream character excision (`Tj`/`TJ` rewriting with kerning preservation + opaque black rectangles) and permanent scanned image pixel blackening & XObject stream replacement.
- Independent post-redaction verification (`VERIFIED`, `PARTIAL`, `FAILED`) by reopening the saved output file and checking extracted text and pixel regions.
- Streaming SHA-256 digests and detached `SHA256withRSA` (`.zksig`) digital signatures.

---

### 2. Redaction Workspace (`RedactionPanel.java`)

The Redaction Workspace implements a 5-stage operator workflow:
1. **Document Selection & Capability Verification**:
   - Validates file format (`.pdf`, `.txt`, `.csv`), checks `%PDF-` header and object structure, and computes the streaming SHA-256 digest.
2. **Page Extraction & OCR Diagnostics**:
   - Displays the document-level `ScanOutcome` badge (`SUCCESS_WITH_MATCHES`, `SUCCESS_NO_MATCHES`, `OCR_UNAVAILABLE`, `LOW_CONFIDENCE_OCR`, `PARTIAL_EXTRACTION_FAILURE`, `EXTRACTION_FAILED`).
   - Displays pages processed, pages failed, native vs. OCR page counts, local OCR engine availability, and a per-page status log.
   - Never reports "No sensitive content found" when OCR is unavailable or extraction failed; provides an **OCR Setup Instructions** dialog with Windows and Linux setup steps.
3. **Candidate Review & Selection Table**:
   - Displays each detection's **Apply?** checkbox, **Category**, **Masked Preview**, **Page & Region Coordinates**, **Method & Confidence**, and **Status & Review Reason** (`[READY]`, `[MANUAL REVIEW]`, `[UNMAPPED - UNSAFE]`).
   - Includes **Select All Redactable**, **Select Verified Ready Only** (skipping low-confidence items flagged for manual review), and **Deselect All** controls.
4. **Sanitization Destination & Detached Signing**:
   - Automatically derives a non-overwriting `.redacted.pdf` / `.redacted.txt` / `.redacted.csv` output path and optionally signs the redacted output with a detached `.zksig` signature.
5. **Execution & Independent Verification Summary**:
   - Displays the output file path, total detected / selected / redacted / skipped / failed counts, explicit `VerificationStatus` (`VERIFIED`, `PARTIAL`, `FAILED`), verification report & risk-reduction disclaimer, and source/output SHA-256 digests.

---

### 3. Settings & OCR Configuration (`SettingsPanel.java`)

- Allows live configuration and testing of the local Tesseract executable path, `tessdata` directory, OCR language code (default `eng`), and scan rendering DPI (`300`).
- Provides Role-Based Access Control (`SECURITY_ADMINISTRATOR`, `REDACTION_OPERATOR`, `AUDITOR_VERIFIER`) and lists all registered context-aware detection rules.
