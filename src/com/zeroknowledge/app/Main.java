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
import com.zeroknowledge.exception.DocumentProcessingException;
import com.zeroknowledge.exception.KeyManagementException;
import com.zeroknowledge.exception.RedactionException;
import com.zeroknowledge.exception.SignatureVerificationException;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.OperationRecord;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.model.VerificationResult;
import com.zeroknowledge.model.VerificationResult.Status;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.AuditService;
import com.zeroknowledge.storage.FileStorageService;
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
import java.util.stream.Stream;

/**
 * Standalone backend test suite and demonstration runner for the
 * Zero-Knowledge Document Redaction and Verification Engine.
 *
 * <p>Executes 16 comprehensive security, parsing, redaction, cryptography,
 * verification, storage, audit-privacy, and PDF capability-boundary tests
 * using only synthetic test data and standard JDK 21 facilities.
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
                    storageService, hashService, accessControl, auditService);
            DocumentService documentService = new DocumentService(
                    storageService, detector, redactionService, accessControl, auditService);
            VerificationService verificationService = new VerificationService(
                    hashService, keyManager, signatureService, accessControl, auditService);

            // Generate shared 3072-bit RSA key pairs once for cryptographic test cases
            System.out.println("\n[Setup] Generating 3072-bit RSA primary and secondary key pairs...");
            KeyPair primaryKeyPair = keyManager.generateKeyPair(KeyManager.DEFAULT_KEY_SIZE);
            KeyPair secondaryKeyPair = keyManager.generateKeyPair(KeyManager.DEFAULT_KEY_SIZE);

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
    // Individual Test Implementations
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
            // Ensure toString() and maskedPreview do not leak full raw secrets
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

        // Approve ONLY the first email, leave the second unapproved
        List<RedactionMatch> userDecision = new ArrayList<>();
        userDecision.add(matches.get(0).withSelection(true));
        userDecision.add(matches.get(1).withSelection(false));

        RedactionResult result = documentService.applyApprovedRedactions(source, userDecision);
        check(result.isSuccess(), "Redaction should succeed");
        check(result.getApprovedMatchesApplied() == 1, "Expected exactly 1 match applied");
        check(!result.getOutputPath().equals(source), "Output path must be distinct from source path");

        String redactedContent = Files.readString(result.getOutputPath(), StandardCharsets.UTF_8);
        check(!redactedContent.contains("primary.secret@corp.example"), "Approved email was not removed");
        check(redactedContent.contains("[REDACTED_EMAIL]"), "Replacement token missing");
        check(redactedContent.contains("public.info@corp.example"), "Unapproved email should be preserved");

        // Ensure original source file is completely untouched
        String originalContentAfter = Files.readString(source, StandardCharsets.UTF_8);
        check(originalContentAfter.equals(content), "Original source file was modified!");
    }

    private static void testOverlappingAndAdjacentMatches(Path tempRoot, DocumentService documentService)
            throws Exception {
        Path source = tempRoot.resolve("overlap_adjacent.txt");
        // Construct text with adjacent items and synthetic overlapping matches
        String text = "Header: [alice@example.com][555-234-5678] Footer.";
        Files.writeString(source, text, StandardCharsets.UTF_8);

        int emailStart = text.indexOf("alice@example.com");
        int emailEnd = emailStart + "alice@example.com".length();
        int phoneStart = text.indexOf("555-234-5678");
        int phoneEnd = phoneStart + "555-234-5678".length();

        // Also create two directly adjacent synthetic matches at "Header" ("Hea" [0,3) and "der" [3,6))
        // and two overlapping matches covering "alice@example.com" ([emailStart, emailStart+10) and [emailStart+5, emailEnd))
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
        // Include UTF-8 BOM (\uFEFF), accented characters, Japanese, and currency symbols
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
        // Row 0: Header
        // Row 1: Contains quoted field with embedded commas, escaped quotes (""), and multiline break (\n)
        // Row 2: Contains SSN and phone
        String csvContent = "ID,FullName,Comments,ContactEmail\r\n"
                + "101,\"Dr. Jane Doe\",\"Patient said, \"\"Call me at (800) 555-0144\n"
                + "or email jane.doe@hospital.org immediately!\"\"\",jane.primary@hospital.org\r\n"
                + "102,Regular User,\"Normal comment, no secrets here\",123-45-6789\r\n";
        Files.writeString(csvFile, csvContent, StandardCharsets.UTF_8);

        List<RedactionMatch> matches = documentService.scanDocument(csvFile);
        // Expected detections:
        // Row 1 Col 1: "Dr. Jane Doe" (PERSON_NAME)
        // Row 1 Col 2: "(800) 555-0144" (PHONE) and "jane.doe@hospital.org" (EMAIL)
        // Row 1 Col 3: "jane.primary@hospital.org" (EMAIL)
        // Row 2 Col 3: "123-45-6789" (SSN)
        check(matches.size() == 5, "Expected 5 CSV cell matches, found: " + matches.size());

        // Approve all 5 matches
        List<RedactionMatch> approved = matches.stream().map(m -> m.withSelection(true)).toList();
        RedactionResult res = documentService.applyApprovedRedactions(csvFile, approved);
        check(res.isSuccess(), "CSV redaction failed");

        String redactedCsv = Files.readString(res.getOutputPath(), StandardCharsets.UTF_8);
        check(!redactedCsv.contains("jane.doe@hospital.org"), "Embedded multiline CSV email was not redacted");
        check(!redactedCsv.contains("(800) 555-0144"), "Embedded multiline CSV phone was not redacted");
        check(!redactedCsv.contains("jane.primary@hospital.org"), "Column 3 email was not redacted");
        check(!redactedCsv.contains("123-45-6789"), "Row 2 SSN was not redacted");
        check(!redactedCsv.contains("Dr. Jane Doe"), "Row 1 titled name was not redacted");

        // Verify column structure was preserved (3 rows, 4 columns in each row)
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
        // 1. Empty TXT and CSV files
        Path emptyTxt = tempRoot.resolve("empty.txt");
        Path emptyCsv = tempRoot.resolve("empty.csv");
        Files.writeString(emptyTxt, "", StandardCharsets.UTF_8);
        Files.writeString(emptyCsv, "", StandardCharsets.UTF_8);

        check(documentService.scanDocument(emptyTxt).isEmpty(), "Empty TXT should return 0 matches");
        check(documentService.scanDocument(emptyCsv).isEmpty(), "Empty CSV should return 0 matches");

        RedactionResult emptyTxtRes = documentService.applyApprovedRedactions(emptyTxt, List.of());
        check(emptyTxtRes.isSuccess(), "Redacting empty TXT file should succeed cleanly");
        check(Files.size(emptyTxtRes.getOutputPath()) == 0, "Redacted empty TXT file should be 0 bytes");

        // 2. Malformed CSV (unclosed quote)
        Path badCsv = tempRoot.resolve("malformed.csv");
        Files.writeString(badCsv, "col1,col2\n\"unclosed quote value,123\n", StandardCharsets.UTF_8);
        boolean threwOnMalformedCsv = false;
        try {
            documentService.scanDocument(badCsv);
        } catch (DocumentProcessingException expected) {
            threwOnMalformedCsv = true;
        }
        check(threwOnMalformedCsv, "Malformed CSV with unclosed quote must throw DocumentProcessingException");

        // 3. Non-existent path
        boolean threwOnMissing = false;
        try {
            documentService.scanDocument(tempRoot.resolve("does_not_exist.txt"));
        } catch (DocumentProcessingException expected) {
            threwOnMissing = true;
        }
        check(threwOnMissing, "Non-existent file path must throw DocumentProcessingException");
    }

    private static void testSha256Consistency(Path tempRoot, HashService hashService) throws Exception {
        // NIST test vector for "abc":
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        Path abcFile = tempRoot.resolve("nist_abc.txt");
        Files.writeString(abcFile, "abc", StandardCharsets.US_ASCII);

        String hash1 = hashService.calculateSha256(abcFile);
        String hash2 = hashService.calculateSha256(abcFile);
        check(hash1.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                "SHA-256 mismatch against NIST 'abc' vector: " + hash1);
        check(hash1.equals(hash2), "SHA-256 must be deterministic across repeated calls");

        // Multi-chunk streaming test (> 64KB buffer size)
        Path largeFile = tempRoot.resolve("large_stream.txt");
        byte[] pattern = "ZeroKnowledgeStreamingHashTestBlock0123456789\n".getBytes(StandardCharsets.UTF_8);
        byte[] fullBytes = new byte[pattern.length * 4000]; // ~180 KB
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

        // Weak key size rejection (< 2048 bits)
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

        // Verify raw file on disk is NOT Java serialized object and does not contain raw PKCS#8 Base64
        String diskContent = Files.readString(encKeyFile, StandardCharsets.UTF_8);
        String rawPkcs8B64 = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        check(!diskContent.contains(rawPkcs8B64), "Encrypted key file leaked raw PKCS#8 private key!");
        check(diskContent.contains("AES/GCM/NoPadding"), "Encrypted key file missing cipher metadata");

        // Load with correct passphrase
        PrivateKey loadedPriv = keyManager.loadEncryptedPrivateKey(encKeyFile, correctPass);
        check(java.util.Arrays.equals(keyPair.getPrivate().getEncoded(), loadedPriv.getEncoded()),
                "Decrypted private key bytes do not match original key");

        // Reject wrong passphrase (AES-GCM authentication tag failure)
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

        // Flip a single byte in the saved document ('$1,000' -> '$9,000')
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

        // 1. Missing signature file
        Path missingSig = tempRoot.resolve("non_existent.zksig");
        VerificationResult missingRes = verificationService.verifyDocument(doc, missingSig, keyPair.getPublic());
        check(!missingRes.isVerified(), "Missing signature must fail");
        check(missingRes.getStatus() == Status.MISSING_SIGNATURE_OR_METADATA,
                "Expected MISSING_SIGNATURE_OR_METADATA, got: " + missingRes.getStatus());

        // 2. Malformed / corrupted signature file
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

        // 1. Attempt to overwrite source file directly must throw RedactionException
        boolean blockedSourceOverwrite = false;
        try {
            documentService.applyApprovedRedactions(source, source, List.of());
        } catch (RedactionException expected) {
            blockedSourceOverwrite = true;
        }
        check(blockedSourceOverwrite, "Redaction engine must block overwriting the original source file");

        // 2. Attempt to write output to an existing directory path must throw RedactionException
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

        // Check in-memory and on-disk audit records for any leakage of raw sensitive values
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

        // Test AccessControlService role restriction (AUDITOR_VERIFIER cannot redact or generate keys)
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
            // Restore SECURITY_ADMINISTRATOR role
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

        // 1. Scanning PDF for sensitive text tokens
        List<RedactionMatch> matches = documentService.scanDocument(pdfFile);
        check(!matches.isEmpty(), "Scanning a PDF should detect sensitive data candidates");

        // 2. Selectively redact matches
        List<RedactionMatch> userDecision = new ArrayList<>();
        for (int i = 0; i < matches.size(); i++) {
            userDecision.add(matches.get(i).withSelection(i % 2 == 0));
        }
        RedactionResult pdfRedactResult = documentService.applyApprovedRedactions(pdfFile, userDecision);
        check(pdfRedactResult.isSuccess(), "PDF redaction should succeed");
        check(pdfRedactResult.getFormat() == DocumentFormat.PDF, "Expected PDF format in result");
        check(Files.exists(pdfRedactResult.getOutputPath()), "Redacted PDF file must exist");
        check(Files.size(pdfRedactResult.getOutputPath()) > 0, "Redacted PDF file must not be empty");

        // 3. Whole-file metadata inspection, SHA-256 hashing, signing, and verification on PDF ARE supported
        DocumentMetadata meta = documentService.inspectDocument(pdfRedactResult.getOutputPath());
        check(meta.getFormat() == DocumentFormat.PDF && meta.getSha256Digest().length() == 64,
                "Whole-file PDF metadata and SHA-256 inspection should succeed");

        Path pdfSig = tempRoot.resolve("sample.pdf.zksig");
        signatureService.signAndSaveDetached(pdfRedactResult.getOutputPath(), keyPair.getPrivate(), keyPair.getPublic(), pdfSig);

        VerificationResult pdfVerify = verificationService.verifyDocument(pdfRedactResult.getOutputPath(), pdfSig, keyPair.getPublic());
        check(pdfVerify.isVerified() && pdfVerify.getStatus() == Status.VALID_SIGNATURE,
                "Whole-file detached signature verification on PDF should succeed");
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
