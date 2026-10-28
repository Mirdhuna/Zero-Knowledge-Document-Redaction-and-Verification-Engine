# Frontend Architecture & Technical Design Document
## Zero-Knowledge Document Redaction & Verification Engine

### 1. Executive Summary

The **Zero-Knowledge Document Redaction & Verification Engine** desktop application is developed with pure **Java 21**, **AWT**, and **Swing**, relying exclusively on standard JDK libraries. It provides a secure, privacy-preserving workflow for detecting sensitive entities (PII, credentials, network addresses), applying redactions, computing deterministic SHA-256 digests, generating detached RSA signatures, and verifying cryptographic authenticity.

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
│ ├── RedactionService (Regex Scanner, Stream Replacer)  │
│ ├── CryptoService    (SHA-256, RSA KeyGen, Sign/Verify)│
│ ├── AuditService     (Thread-safe Event Journaling)    │
│ └── ConfigService    (Properties-based Settings)       │
└──────────────────────────┬─────────────────────────────┘
                           │ Strongly-Typed Models
┌──────────────────────────▼─────────────────────────────┐
│                Domain Models & Metadata                │
│            com.zeroknowledge.model & core              │
├────────────────────────────────────────────────────────┤
│ ├── RedactionMatch      (Candidate coordinates & masks)│
│ ├── RedactionResult     (Status, dual digests, sig)    │
│ ├── VerificationResult  (7-state outcome, diagnostics) │
│ ├── KeyInfo             (Algorithm, size, fingerprint) │
│ ├── OperationRecord     (Audit timestamp, type, status)│
│ └── DocumentMetaData    (File attributes & formatting) │
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
1. **Document Selection**: Inspects file metadata (`core.DocumentMetaData`) and performs engine capability verification.
2. **Scanning**: Executes background `SwingWorker` scanning for sensitive patterns (SSN, Email, Credit Cards, Phone numbers, API secrets, IPv4).
3. **Candidate Review**: Displays matches in a styled `JTable` with checkboxes, masked previews, row/column locations, and rule explanations. Supports individual selection, "Select All", and "Deselect All".
4. **Output & Signing Configuration**: Lets the user specify destination path (strictly prohibiting overwriting the original document) and select an RSA key for detached digital signing.
5. **Execution & Results**: Displays original and redacted SHA-256 digests, redacted count, and detached `.sig` path.

#### `VerificationPanel.java`
- Independent workspace for verifying detached signatures.
- Accepts target document, detached `.sig` file, and an active RSA key or custom X.509 PEM public key.
- Accurately reports 7 distinct cryptographic states:
  - `SIGNATURE_VALID`
  - `VERIFICATION_FAILED`
  - `DOCUMENT_MODIFIED_OR_MISMATCH`
  - `SIGNATURE_MISSING_OR_INVALID`
  - `TRUSTED_PUBLIC_KEY_UNAVAILABLE`
  - `UNSUPPORTED_OPERATION`
  - `VERIFICATION_ERROR`
- Displays computed SHA-256 hash, public key fingerprint, execution time in milliseconds, and technical explanation.

#### `KeyManagementPanel.java`
- RSA Key Pair Generator supporting 2048, 3072, and 4096-bit keys running in background `SwingWorker`.
- Public key inspector with SHA-256 key fingerprint and standard X.509 PEM formatted text view.
- Export public key to `.pem` file.
- Import external public key from `.pem` file.
- Active signing key selector.
- Security advisory banner highlighting key storage boundaries.

#### `AuditPanel.java`
- Provides an immutable local audit log of all security-sensitive operations (`SCAN`, `REDACT`, `SIGN`, `VERIFY`, `KEY_GEN`).
- Live filtering by operation type and status.
- Clear history action with confirmation dialog.

#### `SettingsPanel.java`
- Output and key directory configuration persisted via standard Java properties.
- Toggle individual pattern detection rules (Email, SSN, Credit Card, Phone, API Keys, IP Addresses).
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
   - **Rationale**: Standard Java SE 21 does not bundle a native PDF parser or vector rasterizer. Merely drawing a black box over a PDF creates an unsafe visual illusion where underlying text streams remain intact. The engine honestly reports this limitation and refuses to simulate false security.
2. **Zero-Knowledge Proof Distinction**:
   - **Status**: Not implemented (and clearly disclosed in UI).
   - **Rationale**: SHA-256 digests and RSA asymmetric digital signatures do not constitute Zero-Knowledge Proofs (ZKPs) like zk-SNARKs/zk-STARKs. The application provides data redaction and cryptographic integrity verification without making false ZKP claims.
3. **In-Memory Session Key Storage**:
   - **Status**: Private keys remain held in process memory during the application session.
   - **Rationale**: Without a dedicated HSM or OS credential vault (such as macOS Keychain or Windows DPAPI), serializing plaintext private keys to disk would present a security risk. Public keys can be exported in PEM format; private keys are retained securely in memory.
