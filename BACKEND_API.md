# Zero-Knowledge Document Redaction and Verification Engine — Backend API Reference

This document specifies the frontend integration contract for the **Zero-Knowledge Document Redaction and Verification Engine** backend. All classes are implemented in pure **Java 21** using standard JDK libraries and have zero dependencies on `javax.swing` or `java.awt`.

---

## 1. Package & Class Inventory

### `com.zeroknowledge.backend`
| Class | Responsibility |
| :--- | :--- |
| `DocumentService` | Primary frontend facade for inspecting files, scanning for sensitive data, applying user-approved redactions, and querying format capabilities. |
| `SensitiveDataDetector` | Configurable heuristic regex engine detecting emails, phone numbers, SSNs, credit cards, government IDs, and titled person names. |
| `RedactionService` | Orchestrates format-specific `DocumentHandler` implementations, source-overwrite prevention, and audit logging. |
| `VerificationService` | High-level verification service distinguishing 7 cryptographic and operational outcomes against an explicitly trusted `PublicKey`. |
| `AccessControlService` | Role-based permission checks separating ordinary document redaction from private-key management and signing. |

### `com.zeroknowledge.document`
| Class / Interface | Responsibility |
| :--- | :--- |
| `DocumentFormat` | Enum (`TXT`, `CSV`, `PDF`, `UNSUPPORTED`) defining capability boundaries per file format. |
| `DocumentReader` | Interface for reading and validating raw document content. |
| `DocumentHandler` | Interface extending `DocumentReader` with `scan(...)`, `applyRedactions(...)`, and overlap-safe reverse-offset replacement logic. |
| `TextDocumentHandler` | UTF-8 `.txt` handler supporting BOM stripping, candidate scanning, and verified atomic output writing. |
| `CsvDocumentHandler` | RFC-4180 compliant state-machine `.csv` handler preserving quotes, escaped quotes (`""`), embedded commas, and multiline cells. |
| `PdfDocumentHandler` | Explicit capability boundary for `.pdf`: validates `%PDF-` header and rejects text extraction/redaction while allowing whole-file hashing and detached signature verification. |

### `com.zeroknowledge.crypto`
| Class | Responsibility |
| :--- | :--- |
| `HashService` | Streaming `SHA-256` file and byte-array digest calculation via `MessageDigest`. |
| `KeyManager` | RSA key generation (default 3072-bit), `SHA256:<16-hex>` key IDs, X.509 PEM public-key export/load, and `PBKDF2WithHmacSHA256` + `AES/GCM/NoPadding` encrypted private-key storage. |
| `SignatureService` | Streaming `SHA256withRSA` detached signing and verification over exact file bytes. |
| `SignatureMetadata` | Versioned (`ZK-SIG-1.0`) detached signature container and parser. |

### `com.zeroknowledge.storage`
| Class | Responsibility |
| :--- | :--- |
| `ApplicationConfig` | Immutable configuration for working directories, key store directory, audit log path, default RSA key size (3072), and max document size (50 MB). |
| `FileStorageService` | Safe path validation, strict UTF-8 decoding (`CodingErrorAction.REPORT`), non-overwriting `.redacted` path derivation, and atomic temporary-file replacement. |
| `AuditService` | Thread-safe local audit logger with defense-in-depth secret scrubbing. |

### `com.zeroknowledge.model`
| Class | Responsibility |
| :--- | :--- |
| `RedactionMatch` | Candidate model holding `matchId`, `candidateType`, `ruleId`, `confidence`, `startOffset`, `endOffset`, `rowIndex`, `columnIndex`, `maskedPreview`, `replacementToken`, and `selectedForRedaction`. |
| `RedactionResult` | Immutable result of a redaction operation including source/output paths, SHA-256 digests, count of applied matches, and summary message. |
| `VerificationResult` | Structured verification outcome with `VerificationResult.Status`, boolean `verified`, `userSafeExplanation`, `technicalDetails`, `calculatedDocumentDigest`, `publicKeyId`, and `verifiedAt`. |
| `DocumentMetadata` | File metadata model (`filePath`, `fileName`, `format`, `sizeBytes`, `sha256Digest`, `lastModifiedTime`, `readable`). |
| `OperationRecord` | Privacy-safe audit entry (`timestamp`, `operationType`, `documentIdentifier`, `success`, `details`). |

### `com.zeroknowledge.exception`
| Checked Exception | Thrown When |
| :--- | :--- |
| `DocumentProcessingException` | A file is missing, unreadable, non-UTF-8, malformed CSV, or an unsupported operation (such as PDF text scanning) is requested. |
| `RedactionException` | Match offsets are out of bounds, destination collides with the source file, or writing/validating the redacted output fails. |
| `SignatureVerificationException` | Signing fails, a detached `.zksig` file is missing or malformed, or cryptographic verification encounters a severe error. |
| `KeyManagementException` | RSA key size is invalid, PEM parsing fails, or encrypted private-key wrapping/unwrapping fails (e.g., wrong passphrase). |

---

## 2. Public Method Signatures for Frontend Integration

### 2.1 `DocumentService` (`com.zeroknowledge.backend.DocumentService`)
```java
public DocumentService()
public DocumentService(
        FileStorageService fileStorageService,
        SensitiveDataDetector sensitiveDataDetector,
        RedactionService redactionService,
        AccessControlService accessControlService,
        AuditService auditService)

// Inspect file metadata & SHA-256 digest
public DocumentMetadata inspectDocument(Path filePath)
        throws DocumentProcessingException

// Scan a .txt or .csv file; returns candidates with selectedForRedaction == false
public List<RedactionMatch> scanDocument(Path sourcePath)
        throws DocumentProcessingException

// Apply only matches where match.isSelectedForRedaction() == true
public RedactionResult applyApprovedRedactions(
        Path sourcePath,
        Path outputPath,
        List<RedactionMatch> approvedMatches)
        throws DocumentProcessingException, RedactionException

// Apply approved matches to default safe output path (e.g., report.redacted.txt)
public RedactionResult applyApprovedRedactions(
        Path sourcePath,
        List<RedactionMatch> approvedMatches)
        throws DocumentProcessingException, RedactionException

// Format & capability queries
public DocumentFormat detectFormat(Path filePath)
public List<DocumentFormat> getSupportedFormats()
public boolean isRedactionSupported(Path filePath)
public boolean isVerificationSupported(Path filePath)
public SensitiveDataDetector getSensitiveDataDetector()
```

### 2.2 `VerificationService` (`com.zeroknowledge.backend.VerificationService`)
```java
public VerificationService()
public VerificationService(
        HashService hashService,
        KeyManager keyManager,
        SignatureService signatureService,
        AccessControlService accessControlService,
        AuditService auditService)

// Verify document against detached .zksig file and a trusted PublicKey PEM file on disk
public VerificationResult verifyDocument(
        Path documentPath,
        Path signaturePath,
        Path trustedPublicKeyPath)

// Verify document against detached .zksig file and an in-memory trusted PublicKey
public VerificationResult verifyDocument(
        Path documentPath,
        Path signaturePath,
        PublicKey trustedPublicKey)
```

`VerificationResult.Status` enum values:
- `VALID_SIGNATURE`
- `SIGNATURE_MISMATCH_OR_MODIFIED`
- `MISSING_SIGNATURE_OR_METADATA`
- `INVALID_SIGNATURE_ENCODING`
- `MISSING_OR_UNTRUSTED_PUBLIC_KEY`
- `UNSUPPORTED_OPERATION`
- `PROCESSING_FAILURE`

### 2.3 `HashService` (`com.zeroknowledge.crypto.HashService`)
```java
public HashService()
public String calculateSha256(Path filePath) throws DocumentProcessingException
public String calculateSha256(byte[] data)
public String calculateSha256ForText(String text)
```

### 2.4 `KeyManager` (`com.zeroknowledge.crypto.KeyManager`)
```java
public KeyManager()
public KeyManager(HashService hashService)

// RSA key generation (DEFAULT_KEY_SIZE = 3072, MIN_KEY_SIZE = 2048)
public KeyPair generateKeyPair() throws KeyManagementException
public KeyPair generateKeyPair(int keySizeBits) throws KeyManagementException

// Key identifiers & validation
public String getKeyIdentifier(PublicKey publicKey) throws KeyManagementException
public String getFullKeyFingerprint(PublicKey publicKey) throws KeyManagementException
public void validatePublicKey(PublicKey publicKey) throws KeyManagementException
public void validatePrivateKey(PrivateKey privateKey) throws KeyManagementException

// X.509 PEM Public Key Export & Load
public void exportPublicKey(PublicKey publicKey, Path destinationPath) throws KeyManagementException
public PublicKey loadPublicKey(Path publicKeyPath) throws KeyManagementException
public PublicKey parsePublicKeyPem(String pemContent) throws KeyManagementException

// Encrypted Local Private Key Storage (PBKDF2WithHmacSHA256 + AES/GCM/NoPadding)
public void saveEncryptedPrivateKey(
        PrivateKey privateKey,
        PublicKey publicKey,
        char[] passphrase,
        Path destinationPath) throws KeyManagementException

public PrivateKey loadEncryptedPrivateKey(
        Path encryptedKeyPath,
        char[] passphrase) throws KeyManagementException
```

### 2.5 `SignatureService` (`com.zeroknowledge.crypto.SignatureService`)
```java
public SignatureService()
public SignatureService(HashService hashService, KeyManager keyManager)

// Sign exact bytes of saved artifact and write detached .zksig metadata file
public SignatureMetadata signAndSaveDetached(
        Path documentPath,
        PrivateKey privateKey,
        PublicKey publicKey,
        Path signatureOutputPath) throws SignatureVerificationException

public SignatureMetadata loadDetachedSignature(Path signaturePath)
        throws SignatureVerificationException

public byte[] signFileBytes(Path documentPath, PrivateKey privateKey)
        throws SignatureVerificationException

public boolean verifyFileBytes(Path documentPath, byte[] signatureBytes, PublicKey trustedKey)
        throws SignatureVerificationException

public boolean verifyDetachedSignature(Path documentPath, Path signaturePath, PublicKey trustedKey)
        throws SignatureVerificationException
```

### 2.6 `AccessControlService` (`com.zeroknowledge.backend.AccessControlService`)
```java
public AccessControlService()
public AccessControlService(Role initialRole, AuditService auditService)

public Role getActiveRole()
public void setActiveRole(Role newRole)
public boolean isPermitted(Permission permission)
public void requirePermission(Permission permission) throws SecurityException
```

Roles (`AccessControlService.Role`):
- `AUDITOR_VERIFIER`: Can hash files, load/export public keys, verify signatures, and view audit logs.
- `REDACTION_OPERATOR`: All `AUDITOR_VERIFIER` permissions plus `SCAN_DOCUMENT` and `REDACT_DOCUMENT`.
- `SECURITY_ADMINISTRATOR`: Full permissions including `GENERATE_KEY_PAIR`, `MANAGE_PRIVATE_KEY`, and `SIGN_DOCUMENT`.

---

## 3. File and Metadata Formats

### 3.1 Detached Signature File Format (`.zksig`)
- **Format Version**: `ZK-SIG-1.0`
- **Encoding**: UTF-8 Java `Properties` key-value file.
- **Exact Signed-Byte Representation**: The `SHA256withRSA` signature is computed over the **exact raw bytes of the target document file on disk** (byte `0` through `EOF`). Metadata fields are informational and are cross-checked against the actual document digest and trusted public key after the cryptographic signature check succeeds.
- **Required Fields**:
  - `formatVersion=ZK-SIG-1.0`
  - `signatureAlgorithm=SHA256withRSA`
  - `documentFormat=TXT | CSV | PDF`
  - `documentDigest=<64-char lowercase hex SHA-256>`
  - `publicKeyId=SHA256:<16-char lowercase hex SPKI prefix>`
  - `signatureReference=<signature filename>`
  - `createdAt=<ISO-8601 UTC timestamp>`
  - `signatureBase64=<Base64-encoded raw RSA signature bytes>`

### 3.2 Encrypted Private Key Format (`.zkkey`)
- **Format Version**: `ZK-ENCKEY-1.0`
- **Key Derivation**: `PBKDF2WithHmacSHA256`, `210,000` iterations, 128-bit random salt.
- **Authenticated Encryption**: `AES/GCM/NoPadding` (256-bit key, 96-bit random IV, 128-bit authentication tag) with AAD bound to `ZK-ENCKEY-1.0|<keyId>`.

### 3.3 Public Key Format (`.pem`)
- Standard RFC 7468 X.509 `SubjectPublicKeyInfo` PEM (`-----BEGIN PUBLIC KEY-----` ... `-----END PUBLIC KEY-----`).

---

## 4. Thread-Safety Expectations

- `HashService`, `SignatureService`, `KeyManager`, `FileStorageService`, `RedactionService`, `DocumentService`, and `VerificationService` are **thread-safe** for concurrent calls across Swing `SwingWorker` background threads. Each cryptographic call instantiates its own JCA `MessageDigest`, `Signature`, or `Cipher` instance.
- `SensitiveDataDetector` uses a `CopyOnWriteArrayList` for rules and is thread-safe for concurrent scans and custom rule registration.
- `AuditService` uses a `CopyOnWriteArrayList` for in-memory records and a `ReentrantLock` for atomic file appends.
- `AccessControlService` stores the active `Role` in an `AtomicReference<Role>`.
- `RedactionMatch` has a mutable `selectedForRedaction` flag for UI table binding, plus an immutable copy factory `withSelection(boolean)`.

---

## 5. End-to-End Frontend Integration Example

```java
import com.zeroknowledge.backend.*;
import com.zeroknowledge.crypto.*;
import com.zeroknowledge.model.*;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

public class FrontendExample {
    public void runWorkflow(Path inputTxt) throws Exception {
        DocumentService docService = new DocumentService();
        KeyManager keyManager = new KeyManager();
        SignatureService sigService = new SignatureService();
        VerificationService verifyService = new VerificationService();

        // 1. Scan document for sensitive candidates (returned unapproved by default)
        List<RedactionMatch> candidates = docService.scanDocument(inputTxt);

        // 2. User approves selected candidates in the Swing UI
        for (RedactionMatch candidate : candidates) {
            if ("EMAIL".equals(candidate.getCandidateType())) {
                candidate.setSelectedForRedaction(true);
            }
        }

        // 3. Apply approved redactions to a separate output file
        RedactionResult redactionResult = docService.applyApprovedRedactions(inputTxt, candidates);
        Path redactedFile = redactionResult.getOutputPath();

        // 4. Generate or load 3072-bit RSA key pair and sign the redacted artifact
        KeyPair keyPair = keyManager.generateKeyPair();
        Path sigFile = docService.getFileStorageService().resolveDefaultSignaturePath(redactedFile);
        sigService.signAndSaveDetached(redactedFile, keyPair.getPrivate(), keyPair.getPublic(), sigFile);

        // 5. Verify the redacted artifact against the detached signature and trusted public key
        VerificationResult verification = verifyService.verifyDocument(
                redactedFile, sigFile, keyPair.getPublic());
        System.out.println("Verified: " + verification.isVerified() + " -> " + verification.getUserSafeExplanation());
    }
}
```

---

## 6. PDF Capability Boundary Summary

| Capability | `.txt` | `.csv` | `.pdf` |
| :--- | :---: | :---: | :---: |
| File Metadata & Header Validation | Supported | Supported | Supported (`%PDF-` header check) |
| Streaming SHA-256 Digest | Supported | Supported | Supported (whole-file bytes) |
| Detached RSA Signing (`SHA256withRSA`) | Supported | Supported | Supported (whole-file bytes) |
| Detached RSA Signature Verification | Supported | Supported | Supported (whole-file bytes) |
| Text Extraction & Sensitive Data Scan | Supported | Supported | **Unsupported** (Throws `DocumentProcessingException`) |
| Content Redaction | Supported | Supported | **Unsupported** (`RedactionResult.isSuccess() == false`) |
