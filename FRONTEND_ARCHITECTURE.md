# Frontend Architecture & Technical Design Document
## Zero-Knowledge Document Redaction & Verification Engine

### 1. Executive Summary

The **Zero-Knowledge Document Redaction & Verification Engine** desktop application is developed with pure **Java 21**, **AWT**, and **Swing**, relying exclusively on standard JDK libraries. It provides a secure, privacy-preserving workflow for detecting sensitive entities (PII, credentials, phone numbers, SSNs, payment cards), applying user-confirmed redactions, computing deterministic streaming SHA-256 digests, generating versioned detached RSA signatures (`.zksig`), and verifying cryptographic document integrity against trusted public keys.

---

### 2. Architectural Design & Separation of Concerns

The application follows a clean, decoupled architecture with dependency injection, separating presentation logic from backend cryptographic and scanning services:

```
┌────────────────────────────────────────────────────────┐
│                   Desktop User Interface               │
│               com.zeroknowledge.frontend               │
├────────────────────────────────────────────────────────┤
│ MainFrame (CardLayout Shell, Sidebar, Navigation)      │
│ ├── DashboardPanel      (Metrics, Activity, Launchers) │
│ ├── RedactionPanel      (5-Step Sanitization Workflow) │
│ ├── VerificationPanel   (Detached Signature Verifier)  │
│ ├── KeyManagementPanel  (RSA KeyGen, PEM Export/Import)│
│ ├── AuditPanel          (Local Immutable Event Log)    │
│ ├── SettingsPanel       (Rules, Paths, Educational Doc)│
│ ├── ThemeManager        (Colors, Custom Painters, Font)│
│ └── DialogManager       (Standardized Action Dialogs)  │
└──────────────────────────┬─────────────────────────────┘
                           │ Constructor Dependency Injection
┌──────────────────────────▼─────────────────────────────┐
│                 Backend Service Container              │
│                com.zeroknowledge.backend               │
├────────────────────────────────────────────────────────┤
│ BackendContext (Shared Service Provider)               │
│ ├── DocumentService     (File inspection, scanning)    │
│ ├── SensitiveDataDetector (Configurable regex engine) │
│ ├── RedactionService    (Overlap-safe stream replacer) │
│ ├── VerificationService (7-outcome signature verifier) │
│ ├── AccessControlService (Role-based access control)   │
│ ├── KeyManager          (RSA 3072 keygen & PEM storage)│
│ ├── SignatureService    (Detached ZK-SIG-1.0 signing)  │
│ ├── HashService         (Streaming SHA-256 digests)    │
│ └── AuditService        (Local thread-safe event log)  │
└──────────────────────────┬─────────────────────────────┘
                           │ Strongly-Typed Models
┌──────────────────────────▼─────────────────────────────┐
│                Domain Models & Storage                 │
│         com.zeroknowledge.model & storage              │
├────────────────────────────────────────────────────────┤
│ ├── RedactionMatch      (Candidate coordinates & masks)│
│ ├── RedactionResult     (Status, dual digests, sig)    │
│ ├── VerificationResult  (7-state outcome, diagnostics) │
│ ├── DocumentMetadata    (Format, size, SHA-256 digest) │
│ ├── OperationRecord     (Audit timestamp, type, status)│
│ ├── ApplicationConfig   (Paths, key size, limits)      │
│ └── FileStorageService  (Safe path derivation & I/O)   │
└────────────────────────────────────────────────────────┘
```

---

### 3. Frontend Component Breakdown

#### `MainFrame.java`
- Acts as the primary application frame (`JFrame`).
- Implements a fixed-width dark navy sidebar (`#161B22`) with active indicator tabs and hover transitions.
- Employs `CardLayout` across 6 distinct workspaces to ensure zero window duplication and preserved session state.
- Houses a clean top app bar with breadcrumbs and real-time cryptographic engine status.
- Entry point `main(String[] args)` starts strictly on the AWT Event Dispatch Thread (EDT) via `SwingUtilities.invokeLater`.

#### `DashboardPanel.java`
- Displays real, locally-derived operational metrics (scanned documents, redactions performed, verified signatures, active keys) retrieved from `AuditService`.
- Prominent quick actions for "Redact Document" and "Verify Document".
- Live recent activity table with empty-state handling.
- Security architecture reference sidebar explaining deterministic hashing and detached signatures.

#### `RedactionPanel.java`
Executes an interactive 5-step sanitization workflow:
1. **Document Selection**: Inspects file metadata (`DocumentMetadata`) and performs engine capability verification (`DocumentFormat.isRedactionSupported()`).
2. **Scanning**: Executes background `SwingWorker` scanning for sensitive patterns (SSN, Email, Credit Cards, Phone numbers, Titled Names) via `DocumentService.scanDocument(Path)`.
3. **Candidate Review**: Displays matches in a styled `JTable` with checkboxes, masked previews, row/column coordinates, and rule explanations. Supports individual selection, "Select All", and "Deselect All".
4. **Output & Signing Configuration**: Lets the user specify destination path (strictly prohibiting overwriting the original document) and select an RSA key for detached digital signing.
5. **Execution & Results**: Displays original and redacted SHA-256 digests, redacted count, and detached `.zksig` path.

#### `VerificationPanel.java`
- Independent workspace for verifying detached `.zksig` signatures.
- Accepts target document, detached `.zksig` file, and an active RSA key or custom X.509 PEM public key.
- Accurately reports 7 distinct cryptographic states:
  - `VALID_SIGNATURE`
  - `SIGNATURE_MISMATCH_OR_MODIFIED`
  - `MISSING_SIGNATURE_OR_METADATA`
  - `INVALID_SIGNATURE_ENCODING`
  - `MISSING_OR_UNTRUSTED_PUBLIC_KEY`
  - `UNSUPPORTED_OPERATION`
  - `PROCESSING_FAILURE`
- Displays computed SHA-256 hash, public key ID, and technical explanation.

#### `KeyManagementPanel.java`
- RSA Key Pair Generator supporting 2048, 3072, and 4096-bit keys running in background `SwingWorker`.
- Public key inspector with SHA-256 key identifier (`SHA256:<16-hex>`) and standard X.509 PEM formatted text view.
- Export public key to `.pem` file.
- Import external public key from `.pem` file.
- Encrypted private key backup with user passphrase (AES-256-GCM + PBKDF2).
- Active signing key selector.

#### `AuditPanel.java`
- Provides an immutable local audit log of all security-sensitive operations (`DOCUMENT_SCAN`, `DOCUMENT_REDACT`, `DOCUMENT_SIGN`, `SIGNATURE_VERIFY`, `KEY_GENERATION`).
- Live filtering by operation type and status.
- Clear history action with confirmation dialog.

#### `SettingsPanel.java`
- Working directories and paths from `ApplicationConfig`.
- Role-based Access Control (RBAC) role selection.
- Registered heuristic detection rules inspection (`SensitiveDataDetector.getRules()`).
- Comprehensive educational section defining the mathematical differences between Redaction, Hashing, Digital Signatures, and Zero-Knowledge Proofs.

#### `ThemeManager.java` & `DialogManager.java`
- Restrained, modern palette: Dark charcoal sidebar (`#161B22`), Slate background (`#F8FAFC`), Cards (`#FFFFFF`), Primary Teal/Blue (`#0284C7`), Success Green (`#16A34A`), Warning Amber (`#D97706`), Danger Red (`#DC2626`).
- Antialiased custom button, badge, and card painters.
- Actionable dialogs omitting raw stack traces or internal memory addresses.

---

### 4. Responsiveness and Concurrency Model

All compute-intensive operations execute asynchronously using `javax.swing.SwingWorker`:
1. **File Scanning**: Reads and parses file contents in `doInBackground()`, updating UI state upon completion in `done()` on the EDT.
2. **Redaction & Signing**: Document replacement, SHA-256 calculation, and RSA signing execute on worker threads while displaying progress bars.
3. **Key Generation**: 2048/3072/4096-bit RSA key generation runs in the background, preventing UI freezes.
4. **Signature Verification**: Large file streaming and signature verification execute asynchronously.
5. **Control Guarding**: Conflicting action buttons are disabled during execution and restored upon completion or failure.

---

### 5. Honest List of Incomplete / Unsupported Features

1. **PDF Redaction Limitation**:
   - **Status**: Unsupported in standard JDK runtime.
   - **Rationale**: Standard Java SE 21 does not bundle a native PDF parser or vector rasterizer. Merely drawing a black box over a PDF creates an unsafe visual illusion where underlying text streams remain intact. The engine honestly reports this limitation and refuses to simulate false security. Whole-file SHA-256 hashing and detached RSA signing/verification are supported for PDFs.
2. **Zero-Knowledge Proof Distinction**:
   - **Status**: Not implemented (and clearly disclosed in UI).
   - **Rationale**: SHA-256 digests and RSA asymmetric digital signatures do not constitute Zero-Knowledge Proofs (ZKPs) like zk-SNARKs/zk-STARKs. The application provides data redaction and cryptographic integrity verification without making false ZKP claims.
3. **In-Memory Session Key Storage**:
   - **Status**: Active private keys remain held in process memory during the application session or saved with user passphrase via `KeyManager.saveEncryptedPrivateKey(...)`.
   - **Rationale**: Plaintext private keys are never exposed in the interface or written unencrypted to disk.
