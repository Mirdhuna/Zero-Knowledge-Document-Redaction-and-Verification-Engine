# Zero-Knowledge Document Redaction and Verification Engine — Backend API Reference

This document specifies the backend architecture, OCR integration, detection rules, PDF redaction pipeline, and frontend integration contract for the **Zero-Knowledge Document Redaction and Verification Engine** (Java 21).

---

## 1. Package & Class Inventory

### `com.zeroknowledge.backend`
| Class | Responsibility |
| :--- | :--- |
| `DocumentService` | Primary frontend facade for inspecting files, scanning documents with per-page diagnostics (`scanDocumentWithReport`), applying permanent redactions, and querying capabilities. |
| `SensitiveDataDetector` | Context-aware detection engine supporting Aadhaar (Verhoeff + context), PAN, IFSC, Bank Account numbers, Credit/Debit cards (Luhn + context), labelled CVV & Expiry, Email, Phone, DOB, Names, Addresses, Certificate IDs, Tax IDs/GSTIN, and labelled Financial Amounts, with OCR character-confusion normalization (`O`/`0`, `I`/`1`, `S`/`5`, `B`/`8`). |
| `RedactionService` | Orchestrates format-specific `DocumentHandler` implementations, source-overwrite prevention, post-redaction verification, and privacy-safe audit logging. |
| `VerificationService` | Cryptographic verification service distinguishing 7 outcomes against an explicitly trusted `PublicKey`. |
| `AccessControlService` | Role-based permission checks (`AUDITOR_VERIFIER`, `REDACTION_OPERATOR`, `SECURITY_ADMINISTRATOR`). |

### `com.zeroknowledge.document`
| Class / Interface | Responsibility |
| :--- | :--- |
| `DocumentFormat` | Enum (`TXT`, `CSV`, `PDF`, `UNSUPPORTED`) defining capability boundaries per file format. |
| `DocumentReader` | Interface for reading and validating raw document content. |
| `DocumentHandler` | Interface extending `DocumentReader` with `scan(...)` and `applyRedactions(...)`. |
| `PdfDocumentHandler` | Full page-by-page PDF 1.4+ parser, native text/matrix position extractor (`BT..ET`, `Tm`, `Td`, `TD`, `T*`, `cm`, `/Rotate`, `Tj`, `TJ`), embedded image extractor, local OCR dispatcher, permanent stream character exciser, permanent image pixel blackener, and independent post-redaction verifier. |
| `OcrEngine` | Interface and models (`OcrAvailability`, `OcrWordBox`, `OcrExtractionResult`) for local OCR engines. |
| `TesseractOcrEngine` | Safe `ProcessBuilder` wrapper invoking local `tesseract` (`--version`, `--list-langs`, `<image.png> stdout -l <lang> --psm 6 tsv`) with zero external network uploads. |
| `ImagePreprocessor` | Scanned image preprocessing pipeline: bicubic upscaling, ITU-R BT.601 grayscale conversion, percentile histogram contrast stretching, 3x3 impulse denoising, projection-profile deskewing, Otsu thresholding, and reversible coordinate mapping. |
| `LocalBitmapOcrEngine` | Deterministic local bitmap/pixel-projection OCR engine and CLI runner for offline automated testing. |
| `SyntheticPdfFactory` | Programmatic generator of multi-page selectable, scanned, hybrid, rotated, and low-contrast synthetic test PDFs. |
| `TextDocumentHandler` | UTF-8 `.txt` handler with post-save verification. |
| `CsvDocumentHandler` | RFC-4180 compliant state-machine `.csv` handler preserving cell structure. |

### `com.zeroknowledge.model`
| Class | Responsibility |
| :--- | :--- |
| `PdfBoundingBox` | Immutable 2D bounding box on a 1-based PDF page (`x, y, width, height, pageWidth, pageHeight, rotation`) with pixel conversion and same-line union helpers. |
| `PageExtractionReport` | Per-page extraction report with `PageStatus` (`NATIVE_TEXT_EXTRACTED`, `OCR_EXTRACTED`, `HYBRID_EXTRACTED`, `EMPTY_PAGE`, `LOW_CONFIDENCE_OCR`, `OCR_UNAVAILABLE`, `EXTRACTION_FAILED`). |
| `DocumentScanReport` | Document-level scan report with `ScanOutcome` (`SUCCESS_WITH_MATCHES`, `SUCCESS_NO_MATCHES`, `OCR_UNAVAILABLE`, `LOW_CONFIDENCE_OCR`, `PARTIAL_EXTRACTION_FAILURE`, `EXTRACTION_FAILED`), per-page reports, and matches. |
| `RedactionMatch` | Candidate model holding category, masked preview, 1-based page number, `DetectionMethod` (`NATIVE_TEXT`, `OCR`, `HYBRID`, `CELL_TEXT`), confidence, `detectionReason`, `RedactionStatus` (`REDACTABLE`, `MANUAL_REVIEW_REQUIRED`, `UNMAPPED_UNSAFE`), and `List<PdfBoundingBox>`. |
| `RedactionResult` | Immutable result of redaction execution including `VerificationStatus` (`VERIFIED`, `PARTIAL`, `FAILED`), `verificationReport`, `selectedMatchesCount`, `approvedMatchesApplied`, `skippedMatchesCount`, `failedMatchesCount`, and SHA-256 digests. |

---

## 2. Local Tesseract OCR Setup & Configuration (Windows & Linux)

The engine performs all OCR **strictly locally** and never uploads confidential documents to external OCR services.

### Windows Setup
1. Install Tesseract OCR via Winget:
   ```powershell
   winget install --id UB-Mannheim.TesseractOCR
   ```
   *(Or download the installer from `https://github.com/UB-Mannheim/tesseract/wiki`)*
2. Ensure `C:\Program Files\Tesseract-OCR` is on your system `PATH`, or set the environment variable:
   ```cmd
   set TESSERACT_PATH=C:\Program Files\Tesseract-OCR\tesseract.exe
   set TESSDATA_PREFIX=C:\Program Files\Tesseract-OCR\tessdata
   ```
3. Verify that `eng.traineddata` is present in the `tessdata` directory.

### Linux Setup (Ubuntu / Debian / Kali / Fedora)
1. Install Tesseract and the English language pack:
   ```bash
   # Ubuntu / Debian / Kali
   sudo apt update && sudo apt install -y tesseract-ocr tesseract-ocr-eng

   # Fedora / RHEL
   sudo dnf install -y tesseract tesseract-langpack-eng
   ```
2. Verify installation:
   ```bash
   tesseract --version
   tesseract --list-langs
   ```

### Runtime Configuration Properties
You can also configure OCR via JVM properties or the **Settings** workspace in the desktop GUI:
- `-Dzk.ocr.tesseractPath=/path/to/tesseract`
- `-Dzk.ocr.tessdataDir=/path/to/tessdata`
- `-Dzk.ocr.language=eng`
- `-Dzk.ocr.dpi=300`
- `-Dzk.ocr.minConfidence=0.65`

---

## 3. Build, Run & Automated Testing Commands

### Windows (`run.bat`)
```cmd
REM Build and run all 40+ automated backend, OCR, PDF redaction & integration tests:
run.bat --test

REM Build and launch the Desktop Swing GUI:
run.bat
```

### Linux / macOS (`run.sh`)
```bash
# Build and run all automated tests:
./run.sh --test

# Build and launch the Desktop Swing GUI:
./run.sh
```
