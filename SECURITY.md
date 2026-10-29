# Security Architecture, Threat Model, and Limitations (`SECURITY.md`)

## 1. Security Objectives

The **Zero-Knowledge Document Redaction and Verification Engine** is engineered around five core security guarantees:

1. **No External Uploads (Strictly Local Processing)**: All PDF parsing, image preprocessing, Tesseract OCR execution, sensitive-data detection, redaction, and cryptographic verification run 100% locally. Confidential documents are never uploaded to external OCR or cloud services.
2. **Permanent Content Removal (Never Visual Overlays Alone)**:
   - **Native PDF Text**: Target character spans are physically excised from decompressed `Tj` and `TJ` content stream operators (inserting negative `TJ` kerning displacements in 1/1000 em units so surrounding non-sensitive text layout is preserved) and covered with opaque black rectangles (`re f`), followed by `xref` table reconstruction.
   - **Scanned Page Images**: Target bounding boxes are painted with opaque black pixels (`RGB 0,0,0`) on a new raster copy, and the PDF `/Subtype /Image` XObject stream is permanently replaced with a freshly compressed Flate raster stream so the original unredacted image bytes are never retained in any layer or object.
3. **Independent Post-Redaction Verification (`VERIFIED`, `PARTIAL`, `FAILED`)**:
   - After saving a redacted output file, the engine reopens the saved file from disk, re-extracts all text streams (and re-runs OCR/pixel checks on redacted image regions), and verifies that redacted values are no longer searchable, extractable, or visible.
4. **Cryptographic Authenticity & Source Preservation**:
   - Original source files are never overwritten.
   - Redacted outputs receive a fresh streaming `SHA-256` digest and a new detached `SHA256withRSA` (`.zksig`) signature. Original document signatures are never reused for modified contents.
5. **Zero Secret Leakage in Logs, Previews, or Exceptions**:
   - `RedactionMatch`, `OperationRecord`, `AuditService`, and exception messages mask sensitive values and scrub emails, SSNs, PANs, IFSCs, Aadhaar/card numbers, and PEM blocks before writing audit logs.

---

## 2. Known Limitations & Honest Risk Disclosure

1. **Automated Verification Risk-Reduction Disclaimer**:
   - Automated post-redaction checks verify extracted text streams and rendered pixel regions to substantially reduce the risk of accidental disclosure, but cannot mathematically prove the absence of every possible contextual, semantic, or indirect disclosure. Human review of the final redacted PDF remains recommended for high-assurance releases.
2. **Scanned Image Raster Replacement Trade-offs**:
   - When redacting sensitive regions inside a scanned PDF page image, replacing the `/Subtype /Image` XObject with a newly Flate-compressed raster guarantees that the original unredacted pixels cannot be recovered from the PDF, while keeping unaffected pixels at their original resolution. Scanned image pages remain raster images (non-selectable text) in the output PDF.
3. **Zero-Knowledge Terminology Disclosure**:
   - In this engine, "Zero-Knowledge" refers to zero exposure of redacted secrets in the sanitized output and zero transmission of confidential data to external services. Standard `SHA-256` digests and `SHA256withRSA` detached signatures prove document integrity and signer authenticity, and do not constitute an interactive or non-interactive mathematical Zero-Knowledge Proof (such as a zk-SNARK).
