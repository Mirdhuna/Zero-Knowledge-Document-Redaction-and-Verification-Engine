# Security Architecture, Threat Model, and Limitations (`SECURITY.md`)

## 1. Security Objectives

The **Zero-Knowledge Document Redaction and Verification Engine** backend is engineered around four core security guarantees:

1. **No Unapproved Data Modification**: Sensitive-data detection (`SensitiveDataDetector`) returns candidate `RedactionMatch` instances with `selectedForRedaction = false`. No text is removed unless explicitly approved.
2. **Irreversible Text Redaction & Source Preservation**: Approved sensitive substrings in `.txt` and `.csv` documents are replaced in-place with uniform tokens (e.g., `[REDACTED_EMAIL]`) in a separate output file via atomic temporary-file replacement. Original source files are never overwritten.
3. **Cryptographic Authenticity & Integrity**: Redacted artifacts are hashed with `SHA-256` and signed over their exact file byte stream using `SHA256withRSA` (3072-bit RSA default). Verification requires both the detached signature and an explicitly trusted `PublicKey`.
4. **Zero Secret Leakage in Logs, Previews, or Exceptions**: `RedactionMatch`, `OperationRecord`, `AuditService`, and custom exception classes never expose full sensitive matches, raw document contents, private keys, or passphrases.

---

## 2. Threat Model

### 2.1 Threats Mitigated
- **Post-Redaction Tampering**: Any single-byte modification to a signed artifact invalidates the `SHA256withRSA` signature and results in `VerificationResult.Status.SIGNATURE_MISMATCH_OR_MODIFIED`.
- **Untrusted Sidecar Metadata Spoofing**: An attacker who modifies both a document and the `documentDigest` field inside its `.zksig` metadata file cannot pass verification because `VerificationService` verifies the cryptographic RSA signature directly against the document's byte stream using an explicitly trusted `PublicKey`.
- **Key Substitution Attacks**: If an attacker re-signs a modified document using their own RSA key pair, `VerificationService` compares the trusted public key against both the key identifier and the cryptographic signature, rejecting it with `MISSING_OR_UNTRUSTED_PUBLIC_KEY`.
- **CSV Column Injection / Shifting**: `CsvDocumentHandler` uses a strict RFC-4180 state machine and applies redactions inside individual `(rowIndex, columnIndex)` cells before re-serializing, preventing embedded commas, quotes, or newlines from shifting data into adjacent columns.
- **Offset Corruption on Overlapping/Adjacent Matches**: `DocumentHandler.applyMatchesToText` merges overlapping spans, keeps adjacent spans distinct, and applies replacements from highest offset to lowest so earlier replacements never shift subsequent offsets.
- **Plaintext Private Key Exposure at Rest**: `KeyManager` never uses Java serialization (`ObjectOutputStream`) and never writes unencrypted private keys to disk. Local private keys are encrypted with `PBKDF2WithHmacSHA256` (210,000 iterations, 128-bit random salt) and `AES/GCM/NoPadding` (256-bit key, 96-bit IV, 128-bit authentication tag) with AAD binding.

---

## 3. Known Limitations & Honest Capability Boundaries

### 3.1 PDF Redaction Boundary (Standard JDK 21 Constraint)
- **Why PDF Redaction Is Unsupported**: Standard JDK 21 does not contain a PDF object-stream parser, Flate/LZW decompressor, font CMap decoder, or XRef table builder. Naive approaches—such as running regular expressions over raw PDF bytes or drawing black rectangles over text—leave sensitive text intact inside compressed streams, incremental update revisions, XMP metadata, or search indexes.
- **Engine Behavior**: `PdfDocumentHandler` strictly refuses text scanning and redaction (`RedactionResult.isSuccess() == false`), ensuring the application **never falsely reports** that a PDF has been redacted. Whole-file SHA-256 hashing and detached RSA signature verification remain supported for PDF files.

### 3.2 Heuristic Regex Detection vs. Semantic PII Recognition
- `SensitiveDataDetector` uses regular expressions to detect structured patterns (emails, phone numbers, SSNs, credit cards, government IDs, and honorific-titled names such as `Dr. Jane Doe`).
- Regular expressions are **heuristic**: they cannot detect unstructured contextual secrets, untitled uncommon names, or sensitive business prose unless a matching custom regex rule is added via `SensitiveDataDetector.addCustomRule(...)`. Human review of the document remains essential.

### 3.3 Metadata & Filesystem Remnants Outside Main Body Text
- Redacting `.txt` or `.csv` files removes approved substrings from the ordinary text content of the newly written `.redacted` artifact.
- It does **not** wipe the original unredacted source file from disk, nor does it scrub OS-level filesystem journal remnants, swap files, or external cloud-sync version histories (e.g., OneDrive/Dropbox snapshots).

### 3.4 Local Key Storage & Access Control Limitations
- **Key Storage**: Under the no-third-party-dependency constraint, standard JDK APIs do not provide a cross-platform hardware-backed vault (HSM/TPM). While `KeyManager` protects stored private keys with `PBKDF2-HMAC-SHA256` (210,000 iterations) and `AES-256-GCM`, security against offline brute-force attacks depends on the entropy of the user's passphrase.
- **Local Access Control**: `AccessControlService` enforces separation of duties (`AUDITOR_VERIFIER`, `REDACTION_OPERATOR`, `SECURITY_ADMINISTRATOR`) within the application runtime. However, in a single-user local desktop environment without a remote authentication server or OS kernel separation, a local user with OS administrator/debugger privileges can inspect JVM memory or modify local audit log files.
