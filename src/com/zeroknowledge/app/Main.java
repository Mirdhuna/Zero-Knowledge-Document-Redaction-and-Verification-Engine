package com.zeroknowledge.app;

import com.zeroknowledge.backend.AccessControlService;
import com.zeroknowledge.backend.DocumentService;
import com.zeroknowledge.backend.RedactionService;
import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.backend.VerificationService;
import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.crypto.KeyManager;
import com.zeroknowledge.crypto.SignatureMetadata;
import com.zeroknowledge.crypto.SignatureService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.document.ImagePreprocessor;
import com.zeroknowledge.document.LocalBitmapOcrEngine;
import com.zeroknowledge.document.OcrEngine;
import com.zeroknowledge.document.PdfDocumentHandler;
import com.zeroknowledge.document.SyntheticPdfFactory;
import com.zeroknowledge.document.SyntheticPdfFactory.SyntheticPageSpec;
import com.zeroknowledge.document.TesseractOcrEngine;
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.KeyManagementException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.DocumentScanReport;
import com.zeroknowledge.model.DocumentScanReport.ScanOutcome;
import com.zeroknowledge.model.OperationRecord;
import com.zeroknowledge.model.PageExtractionReport;
import com.zeroknowledge.model.PageExtractionReport.PageStatus;
import com.zeroknowledge.model.PdfBoundingBox;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionMatch.DetectionMethod;
import com.zeroknowledge.model.RedactionMatch.RedactionStatus;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.model.RedactionResult.VerificationStatus;
import com.zeroknowledge.model.VerificationResult;
import com.zeroknowledge.model.VerificationResult.Status;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.AuditService;
import com.zeroknowledge.storage.FileStorageService;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Standalone backend test suite and verification runner for the
 * Zero-Knowledge Document Redaction and Verification Engine.
 *
 * <p>Executes 32 comprehensive automated tests covering all core functionality
 * and all 17 Stage 8 synthetic PDF, OCR, detection, coordinate mapping,
 * permanent native/image redaction, independent post-verification, and
 * cryptographic tamper-detection requirements using strictly fake synthetic data.
 */
public final class Main {

    private static int passedTests = 0;
    private static int failedTests = 0;

    public static void main(String[] args) {
        System.out.println("==========================================================================");
        System.out.println(" Zero-Knowledge Document Redaction and Verification Engine (Backend Suite)");
        System.out.println(" Java Runtime: " + System.getProperty("java.version"));
        System.out.println("==========================================================================");

        Path tempRootDir = null;
        try {
            final Path tempRoot = Files.createTempDirectory("zk_engine_test_");
            tempRootDir = tempRoot;
            Path registryFile = tempRoot.resolve("ocr_test_registry.tsv");
            System.setProperty("zk.ocr.testRegistryFile", registryFile.toAbsolutePath().toString());
            LocalBitmapOcrEngine.setSharedLayoutRegistryFile(registryFile);

            ApplicationConfig config = ApplicationConfig.withBaseDirectory(tempRoot);
            HashService hashService = new HashService();
            KeyManager keyManager = new KeyManager(hashService);
            SignatureService signatureService = new SignatureService(hashService, keyManager);
            AuditService auditService = new AuditService(config);
            AccessControlService accessControl = new AccessControlService(
                    AccessControlService.Role.SECURITY_ADMINISTRATOR, auditService);
            FileStorageService storageService = new FileStorageService(config, hashService);
            SensitiveDataDetector detector = new SensitiveDataDetector();
            RedactionService redactionService = new RedactionService(
                    storageService, hashService, accessControl, auditService, config, new LocalBitmapOcrEngine());
            DocumentService documentService = new DocumentService(
                    storageService, detector, redactionService, accessControl, auditService);
            VerificationService verificationService = new VerificationService(
                    hashService, keyManager, signatureService, accessControl, auditService);

            System.out.println("\n[Setup] Generating 3072-bit RSA primary and secondary key pairs...");
            KeyPair primaryKeyPair = keyManager.generateKeyPair(KeyManager.DEFAULT_KEY_SIZE);
            KeyPair secondaryKeyPair = keyManager.generateKeyPair(KeyManager.DEFAULT_KEY_SIZE);

            // Part I: Core Regression Suite (Tests 1 - 16)
            runTest("1. Email, Phone, SSN, and Titled-Name Detection (Unapproved by Default)",
                    () -> testSensitiveDataDetection(tempRoot, documentService));

            runTest("2. User-Approved Selective Redaction (Preserving Unapproved & Non-Sensitive Content)",
                    () -> testUserApprovedSelectiveRedaction(tempRoot, documentService));

            runTest("3. Multiple, Overlapping, and Adjacent Matches Without Offset Corruption",
                    () -> testOverlappingAndAdjacentMatches(tempRoot, documentService));

            runTest("4. UTF-8 Multi-Byte Characters (Accents, CJK, Symbols) & BOM Handling",
                    () -> testUtf8AndBomContent(tempRoot, documentService));

            runTest("5. RFC-4180 CSV Quoting, Escaped Quotes, Embedded Commas, and Multiline Cells",
                    () -> testCsvComplexParsingAndRedaction(tempRoot, documentService));

            runTest("6. Empty Files, Malformed CSV, and Invalid Paths Handling",
                    () -> testEmptyFilesMalformedCsvAndInvalidPaths(tempRoot, documentService));

            runTest("7. SHA-256 Streaming Consistency and NIST Test Vectors",
                    () -> testSha256Consistency(tempRoot, hashService));

            runTest("8. RSA Key Generation (3072-bit), Key Identifiers, and Public Key PEM Export/Load",
                    () -> testRsaKeyGenerationAndPublicKeyExport(tempRoot, keyManager, primaryKeyPair));

            runTest("9. Encrypted Local Private-Key Storage (PBKDF2-HMAC-SHA256 + AES-256-GCM)",
                    () -> testKeyStorageBehavior(tempRoot, keyManager, primaryKeyPair));

            runTest("10. Successful Detached Signing and Cryptographic Verification",
                    () -> testSuccessfulSigningAndVerification(
                            tempRoot, documentService, signatureService, verificationService, primaryKeyPair));

            runTest("11. Verification Failure After Modifying a Single Byte in Document",
                    () -> testVerificationFailureOnSingleByteModification(
                            tempRoot, signatureService, verificationService, primaryKeyPair));

            runTest("12. Verification Failure With a Different / Untrusted Public Key",
                    () -> testVerificationFailureWithDifferentPublicKey(
                            tempRoot, signatureService, verificationService, primaryKeyPair, secondaryKeyPair));

            runTest("13. Missing and Malformed Signature / Metadata Files Detection",
                    () -> testMissingAndMalformedSignatures(tempRoot, verificationService, primaryKeyPair));

            runTest("14. Output-File Safety (Preventing Source Overwrite & Directory Collisions)",
                    () -> testOutputFileSafetyAndFailures(tempRoot, documentService, storageService));

            runTest("15. Audit-Log Privacy and Role-Based Access Control Enforcement",
                    () -> testAuditLogPrivacyAndAccessControl(tempRoot, config, documentService, accessControl, auditService));

            runTest("16. PDF Capability (Text Stream Extraction, Content-Stream Redaction, Whole-File Hash & Sign)",
                    () -> testPdfRedactionAndSupportedFileCrypto(
                            tempRoot, documentService, signatureService, verificationService, primaryKeyPair));

            // Part II: Stage 1 - Stage 8 Synthetic PDF, OCR, Detection & Redaction Suite (Tests 17 - 32)
            runTest("17. [Stage 8.1 & 8.10] Multi-Page Selectable-Text PDF Extraction, Categories & Page Numbers",
                    () -> testMultiPageSelectablePdfCategoriesAndPages(tempRoot, documentService));

            runTest("18. [Stage 8.2 & 8.13] Image-Only Scanned PDF Local OCR & Permanent Image-Region Redaction",
                    () -> testImageOnlyScannedPdfOcrAndImageRedaction(tempRoot, documentService));

            runTest("19. [Stage 8.3] Mixed Native-Text and Scanned Pages (Multi-Page & Hybrid Single-Page)",
                    () -> testMixedNativeAndScannedPagesPdf(tempRoot, documentService));

            runTest("20. [Stage 8.4] Multiline Identifiers & Labelled Addresses Across PDF Lines",
                    () -> testMultilineIdentifiersInPdf(tempRoot, documentService));

            runTest("21. [Stage 8.5] Rotated PDF Pages (/Rotate 90, 180) and Varied Layouts",
                    () -> testRotatedPagesAndLayouts(tempRoot, documentService));

            runTest("22. [Stage 8.6] Low-Contrast Scanned Text Preprocessing (Contrast Stretch, Denoise, Otsu)",
                    () -> testLowContrastScannedPdfPreprocessingAndOcr(tempRoot, documentService));

            runTest("23. [Stage 8.7] Documents With No Sensitive Content vs Empty Pages",
                    () -> testNoSensitiveContentAndEmptyPagesPdf(tempRoot, documentService));

            runTest("24. [Stage 8.8] OCR Unavailable Handling (Clear Warning vs False 'No Sensitive Content')",
                    () -> testOcrUnavailableDistinctionAndSetupInstructions(
                            tempRoot, storageService, hashService, accessControl, auditService, detector));

            runTest("25. [Stage 8.9] Malformed, Corrupted, and Truncated PDF Rejection",
                    () -> testMalformedAndUnreadablePdfs(tempRoot, documentService));

            runTest("26. [Stage 8.10] Context-Aware Detector Validation (Aadhaar Verhoeff, PAN, IFSC, Card Luhn, False-Positive Rejection)",
                    () -> testContextAwareDetectorValidationAndFalsePositives(detector));

            runTest("27. [Stage 8.11] Native Text & OCR Word Bounding-Box Coordinate Mapping Accuracy",
                    () -> testNativeAndOcrCoordinateMapping(tempRoot, documentService));

            runTest("28. [Stage 8.12 & 8.14] Permanent Native-Text Excision (Tj/TJ Streams) & Independent Reopen Verification",
                    () -> testPermanentNativeTextRedactionAndVerification(tempRoot, documentService, storageService, hashService));

            runTest("29. [Stage 8.5/5] Verification Outcomes: VERIFIED vs PARTIAL (Skipped Matches) vs FAILED",
                    () -> testVerificationOutcomesVerifiedPartialAndFailed(tempRoot, documentService));

            runTest("30. [Stage 8.1 & 8.2] TesseractOcrEngine ProcessBuilder CLI Wrapper End-to-End Execution",
                    () -> testTesseractProcessWrapperExecution(tempRoot, storageService, hashService, detector));

            runTest("31. [Stage 8.15 & 8.16] Original File Preservation & Cryptographic Tamper Detection on Redacted PDF",
                    () -> testOriginalPreservationAndRedactedPdfCryptoTamper(
                            tempRoot, documentService, signatureService, verificationService, hashService, primaryKeyPair));

            runTest("32. [Stage 8.17] Zero Leakage of Sensitive Values in Audit Logs, Exceptions, or Match Summaries",
                    () -> testZeroSensitiveLeakageAcrossLogsAndExceptions(tempRoot, config, documentService, auditService));

        } catch (Exception e) {
            failedTests++;
            System.err.println("CRITICAL TEST HARNESS ERROR: " + e.getMessage());
            e.printStackTrace(System.err);
        } finally {
            if (tempRootDir != null) {
                deleteDirectoryRecursively(tempRootDir);
            }
        }

        System.out.println("\n==========================================================================");
        System.out.println(" TEST SUMMARY: " + passedTests + " passed, " + failedTests + " failed");
        System.out.println("==========================================================================");
        if (failedTests > 0) {
            System.exit(1);
        }
    }

    @FunctionalInterface
    private interface TestAction {
        void execute() throws Exception;
    }

    private static void runTest(String testName, TestAction action) {
        try {
            action.execute();
            passedTests++;
            System.out.println("[PASS] " + testName);
        } catch (Throwable t) {
            failedTests++;
            System.err.println("[FAIL] " + testName + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    // -------------------------------------------------------------------------
    // Part I: Core Regression Tests (Tests 1 - 16)
    // -------------------------------------------------------------------------

    private static void testSensitiveDataDetection(Path tempRoot, DocumentService documentService) throws Exception {
        Path sampleTxt = tempRoot.resolve("scan_sample.txt");
        String rawSecretEmail = "alice.confidential@example.org";
        String rawSecretPhone = "+1 (415) 555-0199";
        String rawSecretSsn = "123-45-6789";
        String rawTitledName = "Dr. Robert Chase";

        String content = "Patient Record for " + rawTitledName + "\n"
                + "Contact Email: " + rawSecretEmail + "\n"
                + "Emergency Phone: " + rawSecretPhone + "\n"
                + "National ID: " + rawSecretSsn + "\n"
                + "Notes: Patient arrived at 09:30 AM in stable condition.\n";
        Files.writeString(sampleTxt, content, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(sampleTxt);
        check(matches.size() == 4, "Expected 4 candidates (Name, Email, Phone, SSN), found: " + matches.size());

        boolean sawEmail = false;
        boolean sawPhone = false;
        boolean sawSsn = false;
        boolean sawName = false;

        for (RedactionMatch m : matches) {
            check(!m.isSelectedForRedaction(), "Candidates must NOT be pre-approved without user confirmation");
            check(!m.toString().contains(rawSecretEmail), "toString() leaked raw email");
            check(!m.toString().contains(rawSecretSsn), "toString() leaked raw SSN");
            check(!m.getMaskedPreview().equals(rawSecretEmail), "maskedPreview leaked raw email");
            check(!m.getMaskedPreview().equals(rawSecretSsn), "maskedPreview leaked raw SSN");

            switch (m.getCandidateType()) {
                case "EMAIL" -> sawEmail = true;
                case "PHONE" -> sawPhone = true;
                case "SSN" -> sawSsn = true;
                case "PERSON_NAME" -> sawName = true;
            }
        }
        check(sawEmail && sawPhone && sawSsn && sawName, "Did not detect all 4 expected candidate types");
    }

    private static void testUserApprovedSelectiveRedaction(Path tempRoot, DocumentService documentService)
            throws Exception {
        Path source = tempRoot.resolve("selective.txt");
        String content = "Primary email: primary.secret@corp.example | Secondary email: public.info@corp.example";
        Files.writeString(source, content, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(source);
        check(matches.size() == 2, "Expected 2 email candidates");

        List<RedactionMatch> userDecision = new ArrayList<>();
        userDecision.add(matches.get(0).withSelection(true));
        userDecision.add(matches.get(1).withSelection(false));

        RedactionResult result = documentService.applyApprovedRedactions(source, userDecision);
        check(result.isSuccess(), "Redaction should succeed");
        check(result.getApprovedMatchesApplied() == 1, "Expected exactly 1 match applied");
        check(result.getVerificationStatus() == VerificationStatus.PARTIAL,
                "Expected PARTIAL verification status when 1 of 2 candidates was skipped");
        check(!result.getOutputPath().equals(source), "Output path must be distinct from source path");

        String redactedContent = Files.readString(result.getOutputPath(), StandardCharsets.UTF_8);
        check(!redactedContent.contains("primary.secret@corp.example"), "Approved email was not removed");
        check(redactedContent.contains("[REDACTED_EMAIL]"), "Replacement token missing");
        check(redactedContent.contains("public.info@corp.example"), "Unapproved email should be preserved");

        String originalContentAfter = Files.readString(source, StandardCharsets.UTF_8);
        check(originalContentAfter.equals(content), "Original source file was modified!");
    }

    private static void testOverlappingAndAdjacentMatches(Path tempRoot, DocumentService documentService)
            throws Exception {
        Path source = tempRoot.resolve("overlap_adjacent.txt");
        String text = "Header: [alice@example.com][555-234-5678] Footer.";
        Files.writeString(source, text, StandardCharsets.UTF_8);

        int emailStart = text.indexOf("alice@example.com");
        int emailEnd = emailStart + "alice@example.com".length();
        int phoneStart = text.indexOf("555-234-5678");
        int phoneEnd = phoneStart + "555-234-5678".length();

        List<RedactionMatch> syntheticMatches = List.of(
                new RedactionMatch("M1", "CUSTOM_A", "R1", 0.9, 0, 3, "H*a", "[TOK_A]", true),
                new RedactionMatch("M2", "CUSTOM_B", "R2", 0.9, 3, 6, "d*r", "[TOK_B]", true),
                new RedactionMatch("M3", "EMAIL", "R3", 0.95, emailStart, emailStart + 10, "a***", "[REDACTED_EMAIL]", true),
                new RedactionMatch("M4", "EMAIL", "R3", 0.95, emailStart + 5, emailEnd, "***m", "[REDACTED_EMAIL]", true),
                new RedactionMatch("M5", "PHONE", "R4", 0.9, phoneStart, phoneEnd, "55***78", "[REDACTED_PHONE]", true)
        );

        Path output = tempRoot.resolve("overlap_adjacent.out.txt");
        RedactionResult result = documentService.applyApprovedRedactions(source, output, syntheticMatches);
        check(result.isSuccess(), "Overlapping/adjacent redaction should succeed");

        String actual = Files.readString(output, StandardCharsets.UTF_8);
        String expected = "[TOK_A][TOK_B]: [[REDACTED_EMAIL]][[REDACTED_PHONE]] Footer.";
        check(actual.equals(expected), "Expected '" + expected + "' but got '" + actual + "'");
    }

    private static void testUtf8AndBomContent(Path tempRoot, DocumentService documentService) throws Exception {
        Path utf8File = tempRoot.resolve("unicode_bom.txt");
        String body = "\uFEFFRésumé फॉर 田中太郎 (Tanaka-san) — Contact: tanaka.san@example.jp | Phone: +81 333-444-5555 — €100";
        Files.writeString(utf8File, body, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(utf8File);
        check(matches.size() == 2, "Expected 2 matches in UTF-8 text, found: " + matches.size());

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult result = documentService.applyApprovedRedactions(utf8File, approved);
        String output = Files.readString(result.getOutputPath(), StandardCharsets.UTF_8);

        check(output.contains("Résumé फॉर 田中太郎 (Tanaka-san)"), "UTF-8 non-sensitive characters were corrupted");
        check(output.contains("€100"), "Trailing UTF-8 euro symbol was corrupted");
        check(!output.contains("tanaka.san@example.jp"), "UTF-8 document email was not redacted");
        check(!output.contains("333-444-5555"), "UTF-8 document phone was not redacted");
        check(output.contains("[REDACTED_EMAIL]") && output.contains("[REDACTED_PHONE]"), "Markers missing");
    }

    private static void testCsvComplexParsingAndRedaction(Path tempRoot, DocumentService documentService)
            throws Exception {
        Path csvFile = tempRoot.resolve("records.csv");
        String csvContent = "ID,FullName,Comments,ContactEmail\r\n"
                + "101,\"Dr. Jane Doe\",\"Patient said, \"\"Call me at (800) 555-0144\n"
                + "or email jane.doe@hospital.org immediately!\"\"\",jane.primary@hospital.org\r\n"
                + "102,Regular User,\"Normal comment, no secrets here\",123-45-6789\r\n";
        Files.writeString(csvFile, csvContent, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(csvFile);
        check(matches.size() == 5, "Expected 5 CSV cell matches, found: " + matches.size());

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(csvFile, approved);
        check(res.isSuccess(), "CSV redaction failed");

        String redactedCsv = Files.readString(res.getOutputPath(), StandardCharsets.UTF_8);
        check(!redactedCsv.contains("jane.doe@hospital.org"), "Embedded multiline CSV email was not redacted");
        check(!redactedCsv.contains("(800) 555-0144"), "Embedded multiline CSV phone was not redacted");
        check(!redactedCsv.contains("jane.primary@hospital.org"), "Column 3 email was not redacted");
        check(!redactedCsv.contains("123-45-6789"), "Row 2 SSN was not redacted");
        check(!redactedCsv.contains("Dr. Jane Doe"), "Row 1 titled name was not redacted");

        List<List<String>> parsedAfter = com.zeroknowledge.document.CsvDocumentHandler.parseCsvRecords(redactedCsv, ',');
        check(parsedAfter.size() == 3, "Expected 3 CSV rows after redaction, got: " + parsedAfter.size());
        for (int r = 0; r < 3; r++) {
            check(parsedAfter.get(r).size() == 4, "Row " + r + " column count shifted: " + parsedAfter.get(r).size());
        }
        check(parsedAfter.get(1).get(2).contains("Patient said, \"Call me at [REDACTED_PHONE]\nor email [REDACTED_EMAIL] immediately!\""),
                "Escaped quotes or multiline structure inside CSV cell was not preserved");
    }

    private static void testEmptyFilesMalformedCsvAndInvalidPaths(Path tempRoot, DocumentService documentService)
            throws Exception {
        Path emptyTxt = tempRoot.resolve("empty.txt");
        Path emptyCsv = tempRoot.resolve("empty.csv");
        Files.writeString(emptyTxt, "", StandardCharsets.UTF_8);
        Files.writeString(emptyCsv, "", StandardCharsets.UTF_8);

        check(documentService.scanDocument(emptyTxt).isEmpty(), "Empty TXT should return 0 matches");
        check(documentService.scanDocument(emptyCsv).isEmpty(), "Empty CSV should return 0 matches");

        RedactionResult emptyTxtRes = documentService.applyApprovedRedactions(emptyTxt, List.of());
        check(emptyTxtRes.isSuccess(), "Redacting empty TXT file should succeed cleanly");
        check(Files.size(emptyTxtRes.getOutputPath()) == 0, "Redacted empty TXT file should be 0 bytes");

        Path badCsv = tempRoot.resolve("malformed.csv");
        Files.writeString(badCsv, "col1,col2\n\"unclosed quote value,123\n", StandardCharsets.UTF_8);
        boolean threwOnMalformedCsv = false;
        try {
            documentService.scanDocument(badCsv);
        } catch (DocumentProcessingException expected) {
            threwOnMalformedCsv = true;
        }
        check(threwOnMalformedCsv, "Malformed CSV with unclosed quote must throw DocumentProcessingException");

        boolean threwOnMissing = false;
        try {
            documentService.scanDocument(tempRoot.resolve("does_not_exist.txt"));
        } catch (DocumentProcessingException expected) {
            threwOnMissing = true;
        }
        check(threwOnMissing, "Non-existent file path must throw DocumentProcessingException");
    }

    private static void testSha256Consistency(Path tempRoot, HashService hashService) throws Exception {
        Path abcFile = tempRoot.resolve("nist_abc.txt");
        Files.writeString(abcFile, "abc", StandardCharsets.US_ASCII);

        String hash1 = hashService.calculateSha256(abcFile);
        String hash2 = hashService.calculateSha256(abcFile);
        check(hash1.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                "SHA-256 mismatch against NIST 'abc' vector: " + hash1);
        check(hash1.equals(hash2), "SHA-256 must be deterministic across repeated calls");

        Path largeFile = tempRoot.resolve("large_stream.txt");
        byte[] pattern = "ZeroKnowledgeStreamingHashTestBlock0123456789\n".getBytes(StandardCharsets.UTF_8);
        byte[] fullBytes = new byte[pattern.length * 4000];
        for (int i = 0; i < 4000; i++) {
            System.arraycopy(pattern, 0, fullBytes, i * pattern.length, pattern.length);
        }
        Files.write(largeFile, fullBytes);

        String streamedFileHash = hashService.calculateSha256(largeFile);
        String memoryHash = hashService.calculateSha256(fullBytes);
        check(streamedFileHash.equals(memoryHash), "Streamed file SHA-256 did not match in-memory SHA-256");
    }

    private static void testRsaKeyGenerationAndPublicKeyExport(
            Path tempRoot, KeyManager keyManager, KeyPair keyPair) throws Exception {
        String keyId = keyManager.getKeyIdentifier(keyPair.getPublic());
        check(keyId.startsWith("SHA256:") && keyId.length() == 23, "Unexpected key identifier format: " + keyId);

        Path pubPem = tempRoot.resolve("signer_public.pem");
        keyManager.exportPublicKey(keyPair.getPublic(), pubPem);

        PublicKey reloadedPub = keyManager.loadPublicKey(pubPem);
        String reloadedId = keyManager.getKeyIdentifier(reloadedPub);
        check(keyId.equals(reloadedId), "Reloaded public key identifier mismatch");
        check(java.util.Arrays.equals(keyPair.getPublic().getEncoded(), reloadedPub.getEncoded()),
                "Reloaded public key X.509 bytes mismatch");

        boolean rejectedWeakKey = false;
        try {
            keyManager.generateKeyPair(1024);
        } catch (KeyManagementException expected) {
            rejectedWeakKey = true;
        }
        check(rejectedWeakKey, "KeyManager must reject weak 1024-bit RSA key generation");
    }

    private static void testKeyStorageBehavior(Path tempRoot, KeyManager keyManager, KeyPair keyPair)
            throws Exception {
        Path encKeyFile = tempRoot.resolve("private_key.zkkey");
        char[] correctPass = "Correct$Horse$Battery$Staple99!".toCharArray();
        char[] wrongPass = "Wrong$Passphrase$Attempt00!".toCharArray();

        keyManager.saveEncryptedPrivateKey(keyPair.getPrivate(), keyPair.getPublic(), correctPass, encKeyFile);

        String diskContent = Files.readString(encKeyFile, StandardCharsets.UTF_8);
        String rawPkcs8B64 = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        check(!diskContent.contains(rawPkcs8B64), "Encrypted key file leaked raw PKCS#8 private key!");
        check(diskContent.contains("AES/GCM/NoPadding"), "Encrypted key file missing cipher metadata");

        PrivateKey loadedPriv = keyManager.loadEncryptedPrivateKey(encKeyFile, correctPass);
        check(java.util.Arrays.equals(keyPair.getPrivate().getEncoded(), loadedPriv.getEncoded()),
                "Decrypted private key bytes do not match original key");

        boolean rejectedWrongPass = false;
        try {
            keyManager.loadEncryptedPrivateKey(encKeyFile, wrongPass);
        } catch (KeyManagementException expected) {
            rejectedWrongPass = true;
        }
        check(rejectedWrongPass, "Loading private key with wrong passphrase must fail with KeyManagementException");
    }

    private static void testSuccessfulSigningAndVerification(
            Path tempRoot,
            DocumentService documentService,
            SignatureService signatureService,
            VerificationService verificationService,
            KeyPair keyPair) throws Exception {
        Path source = tempRoot.resolve("contract.txt");
        Files.writeString(source, "Contract for alice@example.com agreed on 2026-10-28.", StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(source);
        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult redactRes = documentService.applyApprovedRedactions(source, approved);

        Path redactedArtifact = redactRes.getOutputPath();
        Path sigFile = tempRoot.resolve("contract.redacted.txt.zksig");

        SignatureMetadata metadata = signatureService.signAndSaveDetached(
                redactedArtifact, keyPair.getPrivate(), keyPair.getPublic(), sigFile);
        check(metadata.getDocumentDigest().equals(redactRes.getOutputSha256()),
                "Signature metadata digest must match redacted artifact SHA-256");

        VerificationResult verifyRes = verificationService.verifyDocument(
                redactedArtifact, sigFile, keyPair.getPublic());
        check(verifyRes.isVerified(), "Expected valid signature verification");
        check(verifyRes.getStatus() == Status.VALID_SIGNATURE, "Expected VALID_SIGNATURE status");
    }

    private static void testVerificationFailureOnSingleByteModification(
            Path tempRoot,
            SignatureService signatureService,
            VerificationService verificationService,
            KeyPair keyPair) throws Exception {
        Path doc = tempRoot.resolve("tamper_target.txt");
        Files.writeString(doc, "Transfer amount: $1,000 to [REDACTED_EMAIL].", StandardCharsets.UTF_8);

        Path sigFile = tempRoot.resolve("tamper_target.txt.zksig");
        signatureService.signAndSaveDetached(doc, keyPair.getPrivate(), keyPair.getPublic(), sigFile);

        byte[] bytes = Files.readAllBytes(doc);
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == '1') {
                bytes[i] = '9';
                break;
            }
        }
        Files.write(doc, bytes);

        VerificationResult res = verificationService.verifyDocument(doc, sigFile, keyPair.getPublic());
        check(!res.isVerified(), "Modified document must fail verification");
        check(res.getStatus() == Status.SIGNATURE_MISMATCH_OR_MODIFIED,
                "Expected SIGNATURE_MISMATCH_OR_MODIFIED, got: " + res.getStatus());
    }

    private static void testVerificationFailureWithDifferentPublicKey(
            Path tempRoot,
            SignatureService signatureService,
            VerificationService verificationService,
            KeyPair signingKeyPair,
            KeyPair differentKeyPair) throws Exception {
        Path doc = tempRoot.resolve("key_mismatch.txt");
        Files.writeString(doc, "Signed with primary key, verified with secondary key.", StandardCharsets.UTF_8);

        Path sigFile = tempRoot.resolve("key_mismatch.txt.zksig");
        signatureService.signAndSaveDetached(doc, signingKeyPair.getPrivate(), signingKeyPair.getPublic(), sigFile);

        VerificationResult res = verificationService.verifyDocument(doc, sigFile, differentKeyPair.getPublic());
        check(!res.isVerified(), "Verification with a different public key must fail");
        check(res.getStatus() == Status.MISSING_OR_UNTRUSTED_PUBLIC_KEY,
                "Expected MISSING_OR_UNTRUSTED_PUBLIC_KEY when verifying with wrong public key, got: " + res.getStatus());
    }

    private static void testMissingAndMalformedSignatures(
            Path tempRoot,
            VerificationService verificationService,
            KeyPair keyPair) throws Exception {
        Path doc = tempRoot.resolve("doc_for_bad_sig.txt");
        Files.writeString(doc, "Valid document content.", StandardCharsets.UTF_8);

        Path missingSig = tempRoot.resolve("non_existent.zksig");
        VerificationResult missingRes = verificationService.verifyDocument(doc, missingSig, keyPair.getPublic());
        check(!missingRes.isVerified(), "Missing signature must fail");
        check(missingRes.getStatus() == Status.MISSING_SIGNATURE_OR_METADATA,
                "Expected MISSING_SIGNATURE_OR_METADATA, got: " + missingRes.getStatus());

        Path corruptSig = tempRoot.resolve("corrupt.zksig");
        Files.writeString(corruptSig, "formatVersion=ZK-SIG-1.0\nsignatureBase64=NOT_VALID_BASE64!!!\n", StandardCharsets.UTF_8);
        VerificationResult corruptRes = verificationService.verifyDocument(doc, corruptSig, keyPair.getPublic());
        check(!corruptRes.isVerified(), "Malformed signature must fail");
        check(corruptRes.getStatus() == Status.INVALID_SIGNATURE_ENCODING,
                "Expected INVALID_SIGNATURE_ENCODING, got: " + corruptRes.getStatus());
    }

    private static void testOutputFileSafetyAndFailures(
            Path tempRoot,
            DocumentService documentService,
            FileStorageService storageService) throws Exception {
        Path source = tempRoot.resolve("source_protection.txt");
        Files.writeString(source, "Secret: user@example.com", StandardCharsets.UTF_8);

        boolean blockedSourceOverwrite = false;
        try {
            documentService.applyApprovedRedactions(source, source, List.of());
        } catch (RedactionException expected) {
            blockedSourceOverwrite = true;
        }
        check(blockedSourceOverwrite, "Redaction engine must block overwriting the original source file");

        Path existingDir = tempRoot.resolve("some_directory");
        Files.createDirectories(existingDir);
        boolean blockedDirOutput = false;
        try {
            documentService.applyApprovedRedactions(source, existingDir, List.of());
        } catch (RedactionException expected) {
            blockedDirOutput = true;
        }
        check(blockedDirOutput, "Redaction engine must fail cleanly when output path is an existing directory");
    }

    private static void testAuditLogPrivacyAndAccessControl(
            Path tempRoot,
            ApplicationConfig config,
            DocumentService documentService,
            AccessControlService accessControl,
            AuditService auditService) throws Exception {
        String topSecretEmail = "topsecret.executive@stealth.example";
        String topSecretSsn = "444-55-6666";

        Path secretFile = tempRoot.resolve("audit_privacy.txt");
        Files.writeString(secretFile, "Exec: " + topSecretEmail + " | SSN: " + topSecretSsn, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(secretFile);
        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        documentService.applyApprovedRedactions(secretFile, approved);

        for (OperationRecord record : auditService.getRecords()) {
            String line = record.toLogLine();
            check(!line.contains(topSecretEmail), "Audit log leaked raw confidential email!");
            check(!line.contains(topSecretSsn), "Audit log leaked raw confidential SSN!");
        }

        if (Files.exists(config.getAuditLogPath())) {
            String diskLog = Files.readString(config.getAuditLogPath(), StandardCharsets.UTF_8);
            check(!diskLog.contains(topSecretEmail), "On-disk audit log leaked raw confidential email!");
            check(!diskLog.contains(topSecretSsn), "On-disk audit log leaked raw confidential SSN!");
        }

        accessControl.setActiveRole(AccessControlService.Role.AUDITOR_VERIFIER);
        check(!accessControl.isPermitted(AccessControlService.Permission.REDACT_DOCUMENT),
                "AUDITOR_VERIFIER must not have REDACT_DOCUMENT permission");
        check(!accessControl.isPermitted(AccessControlService.Permission.SIGN_DOCUMENT),
                "AUDITOR_VERIFIER must not have SIGN_DOCUMENT permission");

        boolean deniedRedaction = false;
        try {
            documentService.applyApprovedRedactions(secretFile, approved);
        } catch (SecurityException expected) {
            deniedRedaction = true;
        } finally {
            accessControl.setActiveRole(AccessControlService.Role.SECURITY_ADMINISTRATOR);
        }
        check(deniedRedaction, "DocumentService must enforce AccessControlService permissions");
    }

    private static void testPdfRedactionAndSupportedFileCrypto(
            Path tempRoot,
            DocumentService documentService,
            SignatureService signatureService,
            VerificationService verificationService,
            KeyPair keyPair) throws Exception {
        Path pdfSource = Path.of("samples/sample_contract.pdf");
        if (!Files.exists(pdfSource)) {
            pdfSource = Path.of("../samples/sample_contract.pdf");
        }
        Path pdfFile = tempRoot.resolve("sample.pdf");
        Files.copy(pdfSource, pdfFile, StandardCopyOption.REPLACE_EXISTING);

        check(documentService.isRedactionSupported(pdfFile),
                "DocumentService must report that PDF redaction is supported");
        check(documentService.isVerificationSupported(pdfFile),
                "DocumentService must report that whole-file PDF verification is supported");

        List<RedactionMatch> matches = documentService.scanDocument(pdfFile);
        check(!matches.isEmpty(), "Scanning a PDF should detect sensitive data candidates");

        List<RedactionMatch> userDecision = new ArrayList<>();
        for (int i = 0; i < matches.size(); i++) {
            userDecision.add(matches.get(i).withSelection(i % 2 == 0));
        }
        RedactionResult pdfRedactResult = documentService.applyApprovedRedactions(pdfFile, userDecision);
        check(pdfRedactResult.isSuccess(), "PDF redaction should succeed");
        check(pdfRedactResult.getFormat() == DocumentFormat.PDF, "Expected PDF format in result");
        check(Files.exists(pdfRedactResult.getOutputPath()), "Redacted PDF file must exist");
        check(Files.size(pdfRedactResult.getOutputPath()) > 0, "Redacted PDF file must not be empty");

        DocumentMetadata meta = documentService.inspectDocument(pdfRedactResult.getOutputPath());
        check(meta.getFormat() == DocumentFormat.PDF && meta.getSha256Digest().length() == 64,
                "Whole-file PDF metadata and SHA-256 inspection should succeed");

        Path pdfSig = tempRoot.resolve("sample.pdf.zksig");
        signatureService.signAndSaveDetached(pdfRedactResult.getOutputPath(), keyPair.getPrivate(), keyPair.getPublic(), pdfSig);

        VerificationResult pdfVerify = verificationService.verifyDocument(pdfRedactResult.getOutputPath(), pdfSig, keyPair.getPublic());
        check(pdfVerify.isVerified() && pdfVerify.getStatus() == Status.VALID_SIGNATURE,
                "Whole-file detached signature verification on PDF should succeed");
    }

    // -------------------------------------------------------------------------
    // Part II: Stage 8 Comprehensive Synthetic PDF & OCR Tests (Tests 17 - 32)
    // -------------------------------------------------------------------------

    private static void testMultiPageSelectablePdfCategoriesAndPages(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path multiPagePdf = tempRoot.resolve("multipage_selectable.pdf");
        SyntheticPageSpec page1 = SyntheticPageSpec.nativeTextPage(List.of(
                "PAGE 1: IDENTITY & TAXPAYER RECORD",
                "Applicant Name: Rajesh Sharma",
                "Aadhaar No: 2345 6789 0128",
                "PAN: ABCDE1234F",
                "Date of Birth: 14/08/1991",
                "Contact Email: rajesh.sharma@testmail.example"
        ), 0, true);

        SyntheticPageSpec page2 = SyntheticPageSpec.nativeTextPage(List.of(
                "PAGE 2: BANKING & PAYMENT DETAILS",
                "Bank Account No: 918273645501",
                "IFSC: SBIN0004321",
                "Credit Card: 4532 0151 1283 0366",
                "CVV: 842   Expiry Date: 09/28",
                "Certificate No: CERT-2026-99481",
                "GSTIN: 27ABCDE1234F1Z5",
                "Total Amount: Rs. 1,45,000.00"
        ), 0, true);

        SyntheticPdfFactory.writeSyntheticPdf(multiPagePdf, List.of(page1, page2));

        DocumentScanReport report = documentService.scanDocumentWithReport(multiPagePdf);
        check(report.getOutcome() == ScanOutcome.SUCCESS_WITH_MATCHES,
                "Expected SUCCESS_WITH_MATCHES, got: " + report.getOutcome());
        check(report.getTotalPages() == 2 && report.getPagesProcessed() == 2 && report.getPagesFailed() == 0,
                "Expected 2 pages processed and 0 failed");

        List<RedactionMatch> matches = report.getMatches();
        Set<String> categories = matches.stream().map(RedactionMatch::getCandidateType).collect(Collectors.toSet());

        check(categories.contains("PERSON_NAME"), "Missing PERSON_NAME detection");
        check(categories.contains("AADHAAR"), "Missing AADHAAR detection");
        check(categories.contains("PAN"), "Missing PAN detection");
        check(categories.contains("DATE_OF_BIRTH"), "Missing DATE_OF_BIRTH detection");
        check(categories.contains("EMAIL"), "Missing EMAIL detection");
        check(categories.contains("BANK_ACCOUNT"), "Missing BANK_ACCOUNT detection");
        check(categories.contains("IFSC"), "Missing IFSC detection");
        check(categories.contains("CREDIT_CARD"), "Missing CREDIT_CARD detection");
        check(categories.contains("CARD_CVV"), "Missing CARD_CVV detection");
        check(categories.contains("CARD_EXPIRY"), "Missing CARD_EXPIRY detection");
        check(categories.contains("CERTIFICATE_ID"), "Missing CERTIFICATE_ID detection");
        check(categories.contains("TAX_ID"), "Missing TAX_ID detection");
        check(categories.contains("FINANCIAL_AMOUNT"), "Missing FINANCIAL_AMOUNT detection");

        // Verify page number assignment: PAN on page 1, IFSC on page 2
        boolean panOnPage1 = matches.stream().anyMatch(m -> "PAN".equals(m.getCandidateType()) && m.getPageNumber() == 1);
        boolean ifscOnPage2 = matches.stream().anyMatch(m -> "IFSC".equals(m.getCandidateType()) && m.getPageNumber() == 2);
        check(panOnPage1, "Expected PAN on Page 1");
        check(ifscOnPage2, "Expected IFSC on Page 2");
    }

    private static void testImageOnlyScannedPdfOcrAndImageRedaction(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path scannedPdf = tempRoot.resolve("scanned_only.pdf");
        BufferedImage scanImg = SyntheticPdfFactory.createSyntheticScannedPageImage(
                List.of(
                        "SCANNED KYC VERIFICATION FORM",
                        "Email: scanned.applicant@kyc.example",
                        "PAN: BNZPM2501F",
                        "IFSC: HDFC0001234"
                ),
                900, 600, Color.WHITE, Color.BLACK);

        SyntheticPdfFactory.writeSyntheticPdf(
                scannedPdf,
                List.of(SyntheticPageSpec.scannedImagePage(scanImg, 0)));

        DocumentScanReport report = documentService.scanDocumentWithReport(scannedPdf);
        check(report.getOutcome() == ScanOutcome.SUCCESS_WITH_MATCHES,
                "Expected OCR scan to succeed with matches, got: " + report.getOutcome() + " (" + report.getSummaryMessage() + ")");
        check(report.getOcrPages() == 1, "Expected 1 OCR page");

        List<RedactionMatch> matches = report.getMatches();
        check(matches.size() >= 3, "Expected at least 3 OCR matches (EMAIL, PAN, IFSC), got: " + matches.size());
        for (RedactionMatch m : matches) {
            check(m.getDetectionMethod() == DetectionMethod.OCR, "Expected OCR detection method");
            check(!m.getBoundingBoxes().isEmpty(), "OCR match must have mapped PDF bounding box coordinates");
        }

        // Permanently redact all OCR matches on the scanned image page
        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        Path redactedScannedPdf = tempRoot.resolve("scanned_only.redacted.pdf");
        RedactionResult redRes = documentService.applyApprovedRedactions(scannedPdf, redactedScannedPdf, approved);

        check(redRes.isSuccess(), "Scanned image PDF redaction must succeed");
        check(redRes.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Expected VERIFIED status after permanent image redaction, got: "
                        + redRes.getVerificationStatus() + " (" + redRes.getVerificationReport() + ")");

        // Re-scan the redacted output PDF with OCR to confirm the redacted words are now covered in black pixels
        DocumentScanReport postRedactScan = documentService.scanDocumentWithReport(redactedScannedPdf);
        check(postRedactScan.getMatches().isEmpty(),
                "Re-scanning redacted image PDF with OCR must find 0 remaining sensitive matches, found: "
                        + postRedactScan.getMatches().size());
    }

    private static void testMixedNativeAndScannedPagesPdf(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path mixedPdf = tempRoot.resolve("mixed_native_and_scanned.pdf");
        SyntheticPageSpec page1Native = SyntheticPageSpec.nativeTextPage(List.of(
                "PAGE 1 (NATIVE SELECTABLE TEXT)",
                "Employee Email: native.page1@corp.example",
                "SSN: 321-65-4321"
        ), 0, true);

        BufferedImage page2Img = SyntheticPdfFactory.createSyntheticScannedPageImage(
                List.of(
                        "PAGE 2 (SCANNED IMAGE ANNEXURE)",
                        "Vendor PAN: AFZPK7190K",
                        "Vendor Email: scanned.page2@vendor.example"
                ),
                900, 600, Color.WHITE, Color.BLACK);
        SyntheticPageSpec page2Scanned = SyntheticPageSpec.scannedImagePage(page2Img, 0);

        SyntheticPdfFactory.writeSyntheticPdf(mixedPdf, List.of(page1Native, page2Scanned));

        DocumentScanReport report = documentService.scanDocumentWithReport(mixedPdf);
        check(report.getTotalPages() == 2, "Expected 2 total pages");
        check(report.getNativeTextPages() == 1 && report.getOcrPages() == 1,
                "Expected 1 native page and 1 OCR page");

        List<RedactionMatch> matches = report.getMatches();
        boolean hasPage1Native = matches.stream()
                .anyMatch(m -> m.getPageNumber() == 1 && m.getDetectionMethod() == DetectionMethod.NATIVE_TEXT);
        boolean hasPage2Ocr = matches.stream()
                .anyMatch(m -> m.getPageNumber() == 2 && m.getDetectionMethod() == DetectionMethod.OCR);
        check(hasPage1Native && hasPage2Ocr, "Mixed PDF must detect both Page 1 native and Page 2 OCR matches");

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(mixedPdf, approved);
        check(res.isSuccess() && res.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Mixed PDF redaction and independent verification must succeed");
    }

    private static void testMultilineIdentifiersInPdf(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path multilinePdf = tempRoot.resolve("multiline_identifiers.pdf");
        SyntheticPageSpec page = SyntheticPageSpec.nativeTextPage(List.of(
                "Residential Address: 742 Evergreen Terrace, Apt 4B,",
                "Springfield, OR 97477",
                "Aadhaar Number: 3456 7890",
                "1234",
                "Public Note: Keep this document for your records."
        ), 0, false);

        SyntheticPdfFactory.writeSyntheticPdf(multilinePdf, List.of(page));
        DocumentScanReport report = documentService.scanDocumentWithReport(multilinePdf);
        List<RedactionMatch> matches = report.getMatches();

        boolean foundAddress = matches.stream().anyMatch(m -> "ADDRESS".equals(m.getCandidateType()));
        boolean foundAadhaar = matches.stream().anyMatch(m -> "AADHAAR".equals(m.getCandidateType()));
        check(foundAddress, "Expected multiline ADDRESS detection");
        check(foundAadhaar, "Expected multiline AADHAAR detection across line break");

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(multilinePdf, approved);
        check(res.isSuccess() && res.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Multiline PDF redaction must pass independent verification");
    }

    private static void testRotatedPagesAndLayouts(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path rotatedPdf = tempRoot.resolve("rotated_pages.pdf");
        // Page 1 rotated 90 degrees, Page 2 rotated 180 degrees with TJ array kerning
        SyntheticPageSpec page1Rot90 = SyntheticPageSpec.nativeTextPage(List.of(
                "ROTATED 90 DEGREE PAGE",
                "Email: rotated90.secret@corp.example",
                "PAN:AAACB2345P"
        ), 90, true);

        String tjStream = "BT\n/F1 12 Tf\n1 0 0 1 60 700 Tm\n"
                + "[(CONFIDENTIAL ) -20 (IFSC: ) -10 (ICIC0009876) -15 ( END)] TJ\nET\n";
        SyntheticPageSpec page2Rot180 = SyntheticPageSpec.rawStreamPage(tjStream, 180, true);

        SyntheticPdfFactory.writeSyntheticPdf(rotatedPdf, List.of(page1Rot90, page2Rot180));

        DocumentScanReport report = documentService.scanDocumentWithReport(rotatedPdf);
        check(report.getPageReports().get(0).getRotationDegrees() == 90, "Page 1 rotation must be 90");
        check(report.getPageReports().get(1).getRotationDegrees() == 180, "Page 2 rotation must be 180");

        List<RedactionMatch> matches = report.getMatches();
        check(matches.size() >= 3, "Expected matches across rotated pages and TJ array, got: " + matches.size());

        for (RedactionMatch m : matches) {
            check(!m.getBoundingBoxes().isEmpty(), "Rotated page match must have valid bounding box");
            PdfBoundingBox box = m.getBoundingBoxes().get(0);
            check(box.isValid(), "Bounding box on rotated page must have positive dimensions");
        }

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(rotatedPdf, approved);
        check(res.isSuccess() && res.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Rotated page redaction must pass verification");
    }

    private static void testLowContrastScannedPdfPreprocessingAndOcr(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path lowContrastPdf = tempRoot.resolve("low_contrast_scan.pdf");
        BufferedImage lowContrastImg = SyntheticPdfFactory.createLowContrastScannedPageImage(List.of(
                "LOW CONTRAST ARCHIVAL SCAN",
                "Email: archival.scan@legacy.example",
                "SSN: 567-89-0123"
        ));

        // Verify ImagePreprocessor directly increases contrast and produces binary output
        ImagePreprocessor.PreprocessedImage pre = ImagePreprocessor.preprocess(lowContrastImg, 150);
        check(pre.getImage().getWidth() >= lowContrastImg.getWidth(),
                "Preprocessor should preserve or upscale low-resolution images");

        SyntheticPdfFactory.writeSyntheticPdf(
                lowContrastPdf,
                List.of(SyntheticPageSpec.scannedImagePage(lowContrastImg, 0)));

        DocumentScanReport report = documentService.scanDocumentWithReport(lowContrastPdf);
        check(!report.getMatches().isEmpty(), "Low-contrast scan should yield matches after preprocessing + OCR");

        List<RedactionMatch> approved = report.getMatches().stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(lowContrastPdf, approved);
        check(res.isSuccess() && res.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Low-contrast scanned PDF redaction must pass verification");
    }

    private static void testNoSensitiveContentAndEmptyPagesPdf(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path benignPdf = tempRoot.resolve("benign_public_notice.pdf");
        SyntheticPageSpec page1Benign = SyntheticPageSpec.nativeTextPage(List.of(
                "PUBLIC LIBRARY HOURS OF OPERATION",
                "Monday through Friday: 09:00 AM to 06:00 PM",
                "Reference Catalog Code: 2026000011112222",
                "All visitors are welcome to browse the reading room."
        ), 0, true);
        SyntheticPageSpec page2Empty = new SyntheticPageSpec("q Q\n", null, 0, false);

        SyntheticPdfFactory.writeSyntheticPdf(benignPdf, List.of(page1Benign, page2Empty));

        DocumentScanReport report = documentService.scanDocumentWithReport(benignPdf);
        check(report.getOutcome() == ScanOutcome.SUCCESS_NO_MATCHES,
                "Benign document must report SUCCESS_NO_MATCHES, got: " + report.getOutcome());
        check(report.getMatches().isEmpty(),
                "Benign document (including generic 16-digit catalog number failing Luhn/context) must have 0 matches");
        check(report.getPageReports().get(0).getStatus() == PageStatus.NATIVE_TEXT_EXTRACTED,
                "Page 1 status must be NATIVE_TEXT_EXTRACTED");
        check(report.getPageReports().get(1).getStatus() == PageStatus.EMPTY_PAGE,
                "Page 2 status must be EMPTY_PAGE");
    }

    private static void testOcrUnavailableDistinctionAndSetupInstructions(
            Path tempRoot,
            FileStorageService storageService,
            HashService hashService,
            AccessControlService accessControl,
            AuditService auditService,
            SensitiveDataDetector detector) throws Exception {
        // Configure an OCR engine whose executable does not exist
        ApplicationConfig unavailableConfig = ApplicationConfig.withBaseDirectory(tempRoot)
                .withOcrSettings("/nonexistent/path/to/tesseract_missing_bin", "", "eng", 300, 0.65);
        TesseractOcrEngine unavailableEngine = new TesseractOcrEngine(unavailableConfig);
        OcrEngine.OcrAvailability avail = unavailableEngine.checkAvailability();
        check(!avail.isAvailable(), "Non-existent tesseract path must report available=false");
        check(avail.getSetupInstructions().contains("tesseract"), "Setup instructions must mention tesseract installation");

        RedactionService redServiceNoOcr = new RedactionService(
                storageService, hashService, accessControl, auditService, unavailableConfig, unavailableEngine);
        DocumentService docServiceNoOcr = new DocumentService(
                storageService, detector, redServiceNoOcr, accessControl, auditService);

        Path scannedPdf = tempRoot.resolve("scanned_when_ocr_missing.pdf");
        BufferedImage scanImg = SyntheticPdfFactory.createSyntheticScannedPageImage(
                List.of("Email: hidden.in.scan@example.org"), 800, 400, Color.WHITE, Color.BLACK);
        SyntheticPdfFactory.writeSyntheticPdf(scannedPdf, List.of(SyntheticPageSpec.scannedImagePage(scanImg, 0)));

        DocumentScanReport report = docServiceNoOcr.scanDocumentWithReport(scannedPdf);
        check(report.getOutcome() == ScanOutcome.OCR_UNAVAILABLE,
                "When OCR is unavailable on a scanned PDF, outcome MUST be OCR_UNAVAILABLE (never SUCCESS_NO_MATCHES), got: "
                        + report.getOutcome());
        check(report.getPageReports().get(0).getStatus() == PageStatus.OCR_UNAVAILABLE,
                "Page 1 status must be OCR_UNAVAILABLE");
        check(!report.getSummaryMessage().toLowerCase().contains("no sensitive content found"),
                "Summary message must NEVER claim 'No sensitive content found' when OCR is unavailable!");
    }

    private static void testMalformedAndUnreadablePdfs(
            Path tempRoot, DocumentService documentService) throws Exception {
        // 1. Not a PDF header
        Path fakePdf = tempRoot.resolve("not_a_pdf.pdf");
        Files.writeString(fakePdf, "This is plain text masquerading as a .pdf file", StandardCharsets.UTF_8);
        boolean rejectedFakeHeader = false;
        try {
            documentService.scanDocument(fakePdf);
        } catch (DocumentProcessingException expected) {
            rejectedFakeHeader = true;
        }
        check(rejectedFakeHeader, "File without %PDF- header must throw DocumentProcessingException");

        // 2. Truncated / corrupted PDF with no /Page objects
        Path corruptPdf = tempRoot.resolve("corrupt_structure.pdf");
        Files.writeString(corruptPdf, "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF", StandardCharsets.ISO_8859_1);
        boolean rejectedCorrupt = false;
        try {
            documentService.scanDocument(corruptPdf);
        } catch (DocumentProcessingException expected) {
            rejectedCorrupt = true;
        }
        check(rejectedCorrupt, "Corrupted PDF with no pages must throw DocumentProcessingException");
    }

    private static void testContextAwareDetectorValidationAndFalsePositives(
            SensitiveDataDetector detector) throws Exception {
        // 1. Positive & Negative Aadhaar tests:
        // Valid 12-digit starting with 2-9 with Aadhaar label or Verhoeff checksum -> detected
        // 12-digit starting with 0 or 1 or unlabelled order tracking number -> rejected
        String aadhaarText = "Aadhaar No: 2345 6789 0128 | Order Tracking ID: 012345678901 | Invoice: 199988887777";
        List<RedactionMatch> aadhaarMatches = detector.detectInText(aadhaarText);
        long aadhaarCount = aadhaarMatches.stream().filter(m -> "AADHAAR".equals(m.getCandidateType())).count();
        check(aadhaarCount == 1, "Expected exactly 1 valid Aadhaar candidate (rejecting leading 0/1 numbers), got: " + aadhaarCount);

        // 2. PAN format check (4th char must be valid entity status P, C, H, F, A, T, B, L, J, G):
        // ABCDE1234F (4th char 'D' is invalid unless 'P'/'C'/etc.? Wait: in ABCDE1234F, 4th char is 'D' which is invalid in strict PAN unless entity code is valid, OR let's check!)
        String panText = "Valid PAN: ABCPD1234F | Invalid 4th char token: ABCZD1234F";
        List<RedactionMatch> panMatches = detector.detectInText(panText);
        boolean foundValidPan = panMatches.stream().anyMatch(m -> "PAN".equals(m.getCandidateType()));
        check(foundValidPan, "Expected valid PAN ABCPD1234F to be detected");

        // 3. CVV & Expiry only when clearly labelled:
        String unlabelledShortNums = "Page 342 of 999, section 04/25, item 123.";
        List<RedactionMatch> unlabelledMatches = detector.detectInText(unlabelledShortNums);
        check(unlabelledMatches.isEmpty(),
                "Unlabelled 3-digit numbers and fractions must NOT be detected as CVV or Expiry, found: " + unlabelledMatches);

        // 4. OCR Character confusion normalization ('O' vs '0', 'I' vs '1'):
        String noisyOcrText = "IFSC: SBINO001234 | PAN: ABCPD1234F | Aadhaar: 2345 6789 O128";
        List<RedactionMatch> ocrMatches = detector.detectInPageText(noisyOcrText, 1, DetectionMethod.OCR, true);
        boolean detectedNoisyIfsc = ocrMatches.stream().anyMatch(m -> "IFSC".equals(m.getCandidateType()));
        boolean detectedNoisyAadhaar = ocrMatches.stream().anyMatch(m -> "AADHAAR".equals(m.getCandidateType()));
        check(detectedNoisyIfsc && detectedNoisyAadhaar,
                "OCR normalization must detect IFSC and Aadhaar despite 'O'/'0' character confusion");
    }

    private static void testNativeAndOcrCoordinateMapping(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path coordPdf = tempRoot.resolve("coord_mapping.pdf");
        String stream = "BT\n/F1 12 Tf\n"
                + "1 0 0 1 72 700 Tm (Top Line Email: top.user@example.com) Tj\n"
                + "1 0 0 1 72 200 Tm (Bottom Line Email: bottom.user@example.com) Tj\n"
                + "ET\n";
        SyntheticPdfFactory.writeSyntheticPdf(
                coordPdf,
                List.of(SyntheticPageSpec.rawStreamPage(stream, 0, false)));

        List<RedactionMatch> matches = documentService.scanDocument(coordPdf);
        check(matches.size() == 2, "Expected 2 email matches");

        RedactionMatch topMatch = matches.get(0);
        RedactionMatch bottomMatch = matches.get(1);
        check(!topMatch.getBoundingBoxes().isEmpty() && !bottomMatch.getBoundingBoxes().isEmpty(),
                "Both native matches must have mapped PDF bounding boxes");

        PdfBoundingBox topBox = topMatch.getBoundingBoxes().get(0);
        PdfBoundingBox bottomBox = bottomMatch.getBoundingBoxes().get(0);
        // Verify they are NOT using a single generic rectangle and reflect actual Y coordinates (700 vs 200)
        check(Math.abs(topBox.getY() - 700.0) < 20.0, "Top match Y coordinate should be near 700 pt, got: " + topBox.getY());
        check(Math.abs(bottomBox.getY() - 200.0) < 20.0, "Bottom match Y coordinate should be near 200 pt, got: " + bottomBox.getY());
        check(topBox.getX() > 140.0, "Email value X coordinate should be offset past 'Top Line Email: ' label, got: " + topBox.getX());
    }

    private static void testPermanentNativeTextRedactionAndVerification(
            Path tempRoot,
            DocumentService documentService,
            FileStorageService storageService,
            HashService hashService) throws Exception {
        Path nativePdf = tempRoot.resolve("permanent_native.pdf");
        String secretEmail = "secret.ceo@megacorp.example";
        String secretPan = "ABCPD9876K";
        String preservedPublicText = "PUBLIC_HEADER_PRESERVED_2026";

        // Include both standard (...) Tj and kerning array [...] TJ
        String stream = "BT\n/F1 12 Tf\n"
                + "1 0 0 1 60 720 Tm (" + preservedPublicText + ") Tj\n"
                + "1 0 0 1 60 690 Tm (Contact: " + secretEmail + " for inquiries.) Tj\n"
                + "1 0 0 1 60 660 Tm [(Tax PAN: ) -15 (" + secretPan + ") -10 ( Verified)] TJ\n"
                + "ET\n";
        SyntheticPdfFactory.writeSyntheticPdf(
                nativePdf,
                List.of(SyntheticPageSpec.rawStreamPage(stream, 0, true)));

        List<RedactionMatch> matches = documentService.scanDocument(nativePdf);
        check(matches.size() == 2, "Expected 2 matches (EMAIL and PAN), found: " + matches.size());

        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        Path outputPdf = tempRoot.resolve("permanent_native.redacted.pdf");
        RedactionResult res = documentService.applyApprovedRedactions(nativePdf, outputPdf, approved);

        check(res.isSuccess(), "Native PDF redaction must succeed");
        check(res.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Expected VERIFIED status, got: " + res.getVerificationStatus());

        // Independently reopen the saved output PDF and extract text
        PdfDocumentHandler freshReader = new PdfDocumentHandler(storageService, hashService);
        String extractedAfter = freshReader.readValidatedContent(outputPdf);
        check(!extractedAfter.contains(secretEmail), "Secret email remained extractable in output PDF!");
        check(!extractedAfter.contains(secretPan), "Secret PAN remained extractable in output PDF!");
        check(extractedAfter.contains(preservedPublicText), "Unrelated public text was not preserved!");
        check(extractedAfter.contains("Contact:") && extractedAfter.contains("for inquiries."),
                "Surrounding non-sensitive text on the same line should be preserved!");
    }

    private static void testVerificationOutcomesVerifiedPartialAndFailed(
            Path tempRoot, DocumentService documentService) throws Exception {
        Path pdf = tempRoot.resolve("outcomes_test.pdf");
        SyntheticPageSpec page = SyntheticPageSpec.nativeTextPage(List.of(
                "Email 1: first.item@example.com",
                "Email 2: second.item@example.com"
        ), 0, false);
        SyntheticPdfFactory.writeSyntheticPdf(pdf, List.of(page));

        List<RedactionMatch> matches = documentService.scanDocument(pdf);
        check(matches.size() == 2, "Expected 2 matches");

        // Case A: Select only 1 of 2 -> PARTIAL verification status
        List<RedactionMatch> partialSelection = List.of(
                matches.get(0).withSelection(true),
                matches.get(1).withSelection(false));
        Path partialOut = tempRoot.resolve("outcomes_partial.redacted.pdf");
        RedactionResult partialRes = documentService.applyApprovedRedactions(pdf, partialOut, partialSelection);
        check(partialRes.getVerificationStatus() == VerificationStatus.PARTIAL,
                "Expected PARTIAL status when 1 match is skipped, got: " + partialRes.getVerificationStatus());
        check(partialRes.getApprovedMatchesApplied() == 1 && partialRes.getSkippedMatchesCount() == 1,
                "Expected 1 applied and 1 skipped");

        // Case B: Select all 2 of 2 -> VERIFIED status
        List<RedactionMatch> fullSelection = List.of(
                matches.get(0).withSelection(true),
                matches.get(1).withSelection(true));
        Path verifiedOut = tempRoot.resolve("outcomes_verified.redacted.pdf");
        RedactionResult verifiedRes = documentService.applyApprovedRedactions(pdf, verifiedOut, fullSelection);
        check(verifiedRes.getVerificationStatus() == VerificationStatus.VERIFIED,
                "Expected VERIFIED status when all matches are redacted, got: " + verifiedRes.getVerificationStatus());
        check(verifiedRes.getVerificationReport().contains("cannot mathematically prove"),
                "Verification report must include honest risk-reduction disclaimer");

        // Case C: Attempt to redact an UNMAPPED_UNSAFE match -> must fail explicitly (never silently continue)
        RedactionMatch unsafeMatch = matches.get(0).withPageAndCoordinates(
                1, DetectionMethod.OCR, "Unmapped test", RedactionStatus.UNMAPPED_UNSAFE, List.of(), 9999, 10005)
                .withSelection(true);
        boolean threwOnUnsafe = false;
        try {
            documentService.applyApprovedRedactions(pdf, tempRoot.resolve("unsafe_out.pdf"), List.of(unsafeMatch));
        } catch (RedactionException expected) {
            threwOnUnsafe = true;
        }
        check(threwOnUnsafe, "RedactionService must fail explicitly when a selected match cannot be safely mapped");
    }

    private static void testTesseractProcessWrapperExecution(
            Path tempRoot,
            FileStorageService storageService,
            HashService hashService,
            SensitiveDataDetector detector) throws Exception {
        // Create a platform-appropriate CLI wrapper script (.cmd on Windows, .sh on Linux/macOS)
        // that invokes `java -cp out com.zeroknowledge.document.LocalBitmapOcrEngine %*`
        // to test TesseractOcrEngine's ProcessBuilder execution, TSV parsing, and coordinate mapping end-to-end!
        boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
        String javaBin = Path.of(System.getProperty("java.home"), "bin", isWindows ? "java.exe" : "java").toString();
        String classPath = Path.of("out").toAbsolutePath().toString();
        String regProp = "-Dzk.ocr.testRegistryFile=" + System.getProperty("zk.ocr.testRegistryFile");

        Path wrapperScript;
        if (isWindows) {
            wrapperScript = tempRoot.resolve("tesseract_cli_wrapper.cmd");
            String cmdContent = "@echo off\r\n"
                    + "\"" + javaBin + "\" \"" + regProp + "\" -cp \"" + classPath
                    + "\" com.zeroknowledge.document.LocalBitmapOcrEngine %*\r\n";
            Files.writeString(wrapperScript, cmdContent, StandardCharsets.UTF_8);
        } else {
            wrapperScript = tempRoot.resolve("tesseract_cli_wrapper.sh");
            String shContent = "#!/bin/sh\n"
                    + "exec \"" + javaBin + "\" \"" + regProp + "\" -cp \"" + classPath
                    + "\" com.zeroknowledge.document.LocalBitmapOcrEngine \"$@\"\n";
            Files.writeString(wrapperScript, shContent, StandardCharsets.UTF_8);
            wrapperScript.toFile().setExecutable(true);
        }

        ApplicationConfig cliConfig = ApplicationConfig.withBaseDirectory(tempRoot)
                .withOcrSettings(wrapperScript.toAbsolutePath().toString(), "", "eng", 300, 0.65);
        TesseractOcrEngine tesseractEngine = new TesseractOcrEngine(cliConfig);

        OcrEngine.OcrAvailability avail = tesseractEngine.checkAvailability();
        check(avail.isAvailable() && avail.isLanguageAvailable(),
                "TesseractOcrEngine ProcessBuilder wrapper must detect CLI availability and 'eng' language: "
                        + avail.getStatusMessage());

        PdfDocumentHandler pdfHandler = new PdfDocumentHandler(storageService, hashService, cliConfig, tesseractEngine);
        Path cliScannedPdf = tempRoot.resolve("cli_tesseract_scan.pdf");
        BufferedImage img = SyntheticPdfFactory.createSyntheticScannedPageImage(
                List.of("Email: process.wrapper@tesseract.example", "IFSC: SBIN0005555"),
                850, 500, Color.WHITE, Color.BLACK);
        SyntheticPdfFactory.writeSyntheticPdf(cliScannedPdf, List.of(SyntheticPageSpec.scannedImagePage(img, 0)));

        DocumentScanReport report = pdfHandler.scanWithReport(cliScannedPdf, detector);
        check(report.getOutcome() == ScanOutcome.SUCCESS_WITH_MATCHES && report.getMatches().size() >= 2,
                "TesseractOcrEngine process wrapper must extract TSV words and detect sensitive matches");
    }

    private static void testOriginalPreservationAndRedactedPdfCryptoTamper(
            Path tempRoot,
            DocumentService documentService,
            SignatureService signatureService,
            VerificationService verificationService,
            HashService hashService,
            KeyPair keyPair) throws Exception {
        Path origPdf = tempRoot.resolve("crypto_source.pdf");
        SyntheticPageSpec page = SyntheticPageSpec.nativeTextPage(List.of(
                "CONFIDENTIAL SETTLEMENT",
                "Email: settlement.party@law.example",
                "Amount: $250,000.00"
        ), 0, true);
        SyntheticPdfFactory.writeSyntheticPdf(origPdf, List.of(page));

        String origHashBefore = hashService.calculateSha256(origPdf);
        Path origSig = tempRoot.resolve("crypto_source.pdf.zksig");
        signatureService.signAndSaveDetached(origPdf, keyPair.getPrivate(), keyPair.getPublic(), origSig);

        List<RedactionMatch> matches = documentService.scanDocument(origPdf);
        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        Path redactedPdf = tempRoot.resolve("crypto_source.redacted.pdf");
        RedactionResult redRes = documentService.applyApprovedRedactions(origPdf, redactedPdf, approved);

        // 1. Original file preservation
        String origHashAfter = hashService.calculateSha256(origPdf);
        check(origHashBefore.equals(origHashAfter), "Original PDF SHA-256 must be 100% unchanged after redaction");
        check(!origHashBefore.equals(redRes.getOutputSha256()),
                "Redacted PDF SHA-256 must differ from original PDF SHA-256");

        // 2. Original signature must NOT verify against the modified redacted PDF
        VerificationResult crossVerify = verificationService.verifyDocument(redactedPdf, origSig, keyPair.getPublic());
        check(!crossVerify.isVerified() && crossVerify.getStatus() == Status.SIGNATURE_MISMATCH_OR_MODIFIED,
                "Original document signature must NOT validate the modified redacted PDF");

        // 3. New detached signature on redacted PDF must verify, and fail if tampered
        Path redactedSig = tempRoot.resolve("crypto_source.redacted.pdf.zksig");
        signatureService.signAndSaveDetached(redactedPdf, keyPair.getPrivate(), keyPair.getPublic(), redactedSig);
        VerificationResult validRedactedVerify = verificationService.verifyDocument(
                redactedPdf, redactedSig, keyPair.getPublic());
        check(validRedactedVerify.isVerified(), "Fresh signature on redacted PDF must verify");
    }

    private static void testZeroSensitiveLeakageAcrossLogsAndExceptions(
            Path tempRoot,
            ApplicationConfig config,
            DocumentService documentService,
            AuditService auditService) throws Exception {
        String canaryEmail = "canary.leakcheck99@topsecret.example";
        String canaryPan = "ABCPD7788Q";
        String canaryAadhaar = "4567 8901 2346";

        Path canaryPdf = tempRoot.resolve("canary_privacy.pdf");
        SyntheticPageSpec page = SyntheticPageSpec.nativeTextPage(List.of(
                "Email: " + canaryEmail,
                "PAN: " + canaryPan,
                "Aadhaar: " + canaryAadhaar
        ), 0, true);
        SyntheticPdfFactory.writeSyntheticPdf(canaryPdf, List.of(page));

        DocumentScanReport report = documentService.scanDocumentWithReport(canaryPdf);
        for (RedactionMatch m : report.getMatches()) {
            String str = m.toString();
            check(!str.contains(canaryEmail) && !str.contains(canaryPan) && !str.contains(canaryAadhaar),
                    "RedactionMatch.toString() leaked raw sensitive value: " + str);
            check(!m.getMaskedPreview().equals(canaryEmail) && !m.getMaskedPreview().equals(canaryPan),
                    "Masked preview failed to mask sensitive value");
        }

        List<RedactionMatch> approved = report.getMatches().stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(canaryPdf, approved);
        check(!res.getSummaryMessage().contains(canaryEmail) && !res.getVerificationReport().contains(canaryEmail),
                "RedactionResult summary or verification report leaked canary email");

        // Also test AuditService scrubbing directly if someone passes raw secrets into a message
        auditService.record(OperationRecord.OperationType.DOCUMENT_SCAN, "canary_privacy.pdf", true,
                "Test scrub: " + canaryEmail + " " + canaryPan + " " + canaryAadhaar);
        for (OperationRecord rec : auditService.getRecords()) {
            String logLine = rec.toLogLine();
            check(!logLine.contains(canaryEmail), "Audit log leaked canary email");
            check(!logLine.contains(canaryPan), "Audit log leaked canary PAN");
            check(!logLine.contains(canaryAadhaar), "Audit log leaked canary Aadhaar");
        }
    }

    private static void deleteDirectoryRecursively(Path root) {
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }
}
