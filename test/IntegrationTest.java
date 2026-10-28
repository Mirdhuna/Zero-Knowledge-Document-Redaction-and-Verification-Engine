package test;

import com.zeroknowledge.backend.*;
import com.zeroknowledge.model.*;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

/**
 * Headless integration and verification test suite.
 * Validates real cryptographic operations, document scanning, redaction,
 * signature creation, tamper detection, and audit logging.
 */
public class IntegrationTest {

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;

        System.out.println("==================================================");
        System.out.println("Zero-Knowledge Redaction & Verification Engine Tests");
        System.out.println("==================================================");

        try {
            // Setup services
            File tempLog = File.createTempFile("test_audit", ".log");
            tempLog.deleteOnExit();
            AuditService auditService = new AuditService(tempLog);
            CryptoService cryptoService = new CryptoService();
            RedactionService redactionService = new RedactionService();
            ConfigService configService = new ConfigService();
            BackendContext context = new BackendContext(redactionService, cryptoService, auditService, configService);

            // Test 1: Key Generation
            System.out.print("[TEST 1] RSA Key Generation (2048 & 3072 bit)... ");
            KeyInfo k2048 = cryptoService.generateKeyPair(2048, "test-2048");
            KeyInfo k3072 = cryptoService.generateKeyPair(3072, "test-3072");
            if (k2048 != null && k3072 != null && k2048.getKeySizeBits() == 2048 && k3072.getKeySizeBits() == 3072) {
                System.out.println("PASSED (Fingerprint: " + k2048.getFingerprintSha256().substring(0, 16) + "...)");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 2: Public Key Export and Import (PEM)
            System.out.print("[TEST 2] Public Key Export and Reload (X.509 PEM)... ");
            File tempPem = File.createTempFile("test_pubkey", ".pem");
            tempPem.deleteOnExit();
            KeyPair kp = cryptoService.getKeyPair("test-2048");
            cryptoService.exportPublicKeyToPemFile(kp.getPublic(), tempPem);
            PublicKey reloadedPk = cryptoService.loadPublicKeyFromPemFile(tempPem);
            if (reloadedPk != null && cryptoService.computeKeyFingerprint(reloadedPk).equals(k2048.getFingerprintSha256())) {
                System.out.println("PASSED");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 3: Document Scanning
            System.out.print("[TEST 3] Sensitive PII & Token Scanning... ");
            File sampleDoc = File.createTempFile("customer_data", ".txt");
            sampleDoc.deleteOnExit();
            String docContent = "Customer Record:\n" +
                    "Name: Alice Walker\n" +
                    "Email: alice.walker@secure-enterprise.org\n" +
                    "SSN: 123-45-6789\n" +
                    "Card: 4111-2222-3333-4444\n" +
                    "Phone: 415-555-2671\n" +
                    "API Secret: sec_token_1234567890abcdef12345678\n" +
                    "Server IP: 192.168.1.100\n";
            Files.writeString(sampleDoc.toPath(), docContent);

            List<RedactionMatch> matches = redactionService.scanDocument(sampleDoc, Set.of("EMAIL", "SSN", "CREDIT_CARD", "PHONE", "API_KEY", "IP_ADDRESS"));
            if (matches.size() == 6) {
                System.out.println("PASSED (Detected " + matches.size() + " matches: Email, SSN, Card, Phone, API Key, IP)");
                passed++;
            } else {
                System.out.println("FAILED (Found " + matches.size() + " matches, expected 6)");
                failed++;
            }

            // Test 4: Document Redaction and Detached Signing
            System.out.print("[TEST 4] Redaction Execution & Detached Digital Signing... ");
            File redactedDoc = File.createTempFile("customer_data_redacted", ".txt");
            redactedDoc.deleteOnExit();
            File sigFile = new File(redactedDoc.getAbsolutePath() + ".sig");
            sigFile.deleteOnExit();

            RedactionResult redResult = redactionService.applyRedaction(
                    sampleDoc,
                    redactedDoc,
                    matches,
                    true,
                    kp,
                    cryptoService
            );

            if (redResult.isSuccess() && redResult.isSigned() && sigFile.exists()) {
                String redactedContent = Files.readString(redactedDoc.toPath());
                boolean hasMasks = redactedContent.contains("[REDACTED:EMAIL]") &&
                        redactedContent.contains("[REDACTED:SSN]") &&
                        redactedContent.contains("[REDACTED:CREDIT_CARD]");
                boolean rawLeaked = redactedContent.contains("alice.walker@secure-enterprise.org") ||
                        redactedContent.contains("123-45-6789");

                if (hasMasks && !rawLeaked) {
                    System.out.println("PASSED (SHA-256: " + redResult.getRedactedFileSha256().substring(0, 16) + "...)");
                    passed++;
                } else {
                    System.out.println("FAILED (Sanitization check failed)");
                    failed++;
                }
            } else {
                System.out.println("FAILED (Redaction error: " + redResult.getErrorMessage() + ")");
                failed++;
            }

            // Test 5: Signature Verification (Valid state)
            System.out.print("[TEST 5] Signature Verification on Intact Redacted Document... ");
            VerificationResult verResult = cryptoService.verifySignature(redactedDoc, sigFile, kp.getPublic());
            if (verResult.getStatus() == VerificationResult.Status.SIGNATURE_VALID) {
                System.out.println("PASSED (Status: " + verResult.getStatus().getDisplayName() + ")");
                passed++;
            } else {
                System.out.println("FAILED (Result: " + verResult.getStatus() + ")");
                failed++;
            }

            // Test 6: Tamper Detection (Document Modified)
            System.out.print("[TEST 6] Tamper Detection (Tampered Document Content)... ");
            File tamperedDoc = File.createTempFile("tampered_redacted", ".txt");
            tamperedDoc.deleteOnExit();
            Files.writeString(tamperedDoc.toPath(), Files.readString(redactedDoc.toPath()) + " "); // Tamper by 1 whitespace
            VerificationResult tamperResult = cryptoService.verifySignature(tamperedDoc, sigFile, kp.getPublic());
            if (tamperResult.getStatus() == VerificationResult.Status.DOCUMENT_MODIFIED_OR_MISMATCH) {
                System.out.println("PASSED (Correctly rejected: " + tamperResult.getStatus().getDisplayName() + ")");
                passed++;
            } else {
                System.out.println("FAILED (Expected mismatch, got: " + tamperResult.getStatus() + ")");
                failed++;
            }

            // Test 7: Tamper Detection (Tampered Signature File)
            System.out.print("[TEST 7] Tamper Detection (Corrupted Signature)... ");
            File badSig = File.createTempFile("corrupted", ".sig");
            badSig.deleteOnExit();
            Files.writeString(badSig.toPath(), "Corrupted Signature Bytes");
            VerificationResult badSigResult = cryptoService.verifySignature(redactedDoc, badSig, kp.getPublic());
            if (!badSigResult.isValid()) {
                System.out.println("PASSED (Correctly rejected invalid signature)");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 8: PDF Rejection Handling
            System.out.print("[TEST 8] Capability Check: Unsupported PDF Document... ");
            File dummyPdf = File.createTempFile("test_doc", ".pdf");
            dummyPdf.deleteOnExit();
            boolean threwExpected = false;
            try {
                redactionService.scanDocument(dummyPdf, null);
            } catch (UnsupportedOperationException uoe) {
                threwExpected = true;
            }
            if (threwExpected) {
                System.out.println("PASSED (Honest refusal to simulate unsafe visual PDF redaction)");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 9: Audit Logging and Retrieval
            System.out.print("[TEST 9] Audit Service Event Logging & Querying... ");
            auditService.logOperation(OperationRecord.OperationType.SCAN, "doc1.txt", OperationRecord.Status.SUCCESS, "Scan test");
            auditService.logOperation(OperationRecord.OperationType.REDACT, "doc1.txt", OperationRecord.Status.SUCCESS, "Redact test");
            auditService.logOperation(OperationRecord.OperationType.VERIFY, "doc1.txt", OperationRecord.Status.SUCCESS, "Verify test");
            if (auditService.getScannedCount() >= 1 &&
                    auditService.getRedactedCount() >= 1 &&
                    auditService.getVerifiedCount() >= 1) {
                System.out.println("PASSED (All metrics recorded)");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

        } catch (Exception e) {
            System.err.println("Unexpected test failure: " + e.getMessage());
            e.printStackTrace();
            failed++;
        }

        System.out.println("==================================================");
        System.out.println("Test Results: " + passed + " passed, " + failed + " failed");
        System.out.println("==================================================");

        if (failed > 0) {
            System.exit(1);
        }
    }
}
