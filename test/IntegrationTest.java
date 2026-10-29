package test;

import com.zeroknowledge.backend.DocumentService;
import com.zeroknowledge.backend.VerificationService;
import com.zeroknowledge.crypto.KeyManager;
import com.zeroknowledge.crypto.SignatureService;
import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.frontend.BackendContext;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.model.VerificationResult;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Headless integration and verification test suite for the Frontend-Backend integration.
 */
public class IntegrationTest {

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;

        System.out.println("==================================================");
        System.out.println("Zero-Knowledge Frontend-Backend Integration Tests");
        System.out.println("==================================================");

        try {
            BackendContext context = new BackendContext();
            DocumentService docService = context.getDocumentService();
            KeyManager keyManager = context.getKeyManager();
            SignatureService sigService = context.getSignatureService();
            VerificationService verifyService = context.getVerificationService();

            // Test 1: Key Generation (3072-bit RSA)
            System.out.print("[TEST 1] KeyManager RSA 3072-bit generation... ");
            KeyPair kp = keyManager.generateKeyPair(3072);
            String keyId = keyManager.getKeyIdentifier(kp.getPublic());
            if (kp != null && keyId.startsWith("SHA256:")) {
                System.out.println("PASSED (" + keyId + ")");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 2: Public Key Export and Reload
            System.out.print("[TEST 2] Public Key Export & Load (X.509 PEM)... ");
            Path tempPem = Files.createTempFile("test_key", ".pem");
            keyManager.exportPublicKey(kp.getPublic(), tempPem);
            PublicKey reloaded = keyManager.loadPublicKey(tempPem);
            Files.deleteIfExists(tempPem);
            if (reloaded != null && keyManager.getKeyIdentifier(reloaded).equals(keyId)) {
                System.out.println("PASSED");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 3: Document Scanning
            System.out.print("[TEST 3] DocumentService Sensitive Data Scanning... ");
            Path sampleFile = Files.createTempFile("cust_data", ".txt");
            Files.writeString(sampleFile, "Customer Record: John Doe\nEmail: john.doe@example.com\nPhone: (555) 123-4567\nSSN: 000-12-3456\n");
            List<RedactionMatch> candidates = docService.scanDocument(sampleFile);
            if (!candidates.isEmpty()) {
                System.out.println("PASSED (Detected " + candidates.size() + " matches)");
                passed++;
            } else {
                System.out.println("FAILED (No matches found)");
                failed++;
            }

            // Test 4: Selective Redaction & Detached Signing
            System.out.print("[TEST 4] Approved Redaction Execution & .zksig Signing... ");
            for (RedactionMatch m : candidates) {
                m.setSelectedForRedaction(true);
            }
            Path redactedFile = context.getDocumentService().getFileStorageService().resolveDefaultRedactedOutputPath(sampleFile);
            RedactionResult redResult = docService.applyApprovedRedactions(sampleFile, redactedFile, candidates);

            Path sigFile = context.getDocumentService().getFileStorageService().resolveDefaultSignaturePath(redactedFile);
            sigService.signAndSaveDetached(redactedFile, kp.getPrivate(), kp.getPublic(), sigFile);

            if (redResult.isSuccess() && Files.exists(redactedFile) && Files.exists(sigFile)) {
                System.out.println("PASSED (Applied " + redResult.getApprovedMatchesApplied() + " redactions)");
                passed++;
            } else {
                System.out.println("FAILED");
                failed++;
            }

            // Test 5: Signature Verification (Valid state)
            System.out.print("[TEST 5] VerificationService on Valid Redacted Document... ");
            VerificationResult verResult = verifyService.verifyDocument(redactedFile, sigFile, kp.getPublic());
            if (verResult.getStatus() == VerificationResult.Status.VALID_SIGNATURE && verResult.isVerified()) {
                System.out.println("PASSED (Status: " + verResult.getStatus() + ")");
                passed++;
            } else {
                System.out.println("FAILED (" + verResult.getStatus() + ": " + verResult.getUserSafeExplanation() + ")");
                failed++;
            }

            // Test 6: Tamper Detection
            System.out.print("[TEST 6] Tamper Detection (Tampered Document)... ");
            Path tampered = Files.createTempFile("tampered", ".txt");
            Files.writeString(tampered, Files.readString(redactedFile) + " ");
            VerificationResult tamperRes = verifyService.verifyDocument(tampered, sigFile, kp.getPublic());
            Files.deleteIfExists(tampered);
            if (tamperRes.getStatus() == VerificationResult.Status.SIGNATURE_MISMATCH_OR_MODIFIED) {
                System.out.println("PASSED (Rejected: " + tamperRes.getStatus() + ")");
                passed++;
            } else {
                System.out.println("FAILED (Expected mismatch, got: " + tamperRes.getStatus() + ")");
                failed++;
            }

            // Test 7: PDF Capability & Redaction Support Check
            System.out.print("[TEST 7] PDF Content Stream Scan & Redaction Check... ");
            Path samplePdf = Path.of("samples/sample_contract.pdf");
            if (!Files.exists(samplePdf)) {
                samplePdf = Path.of("../samples/sample_contract.pdf");
            }
            DocumentFormat fmt = docService.detectFormat(samplePdf);
            boolean redactionSupported = fmt.isRedactionSupported();
            List<RedactionMatch> pdfMatches = docService.scanDocument(samplePdf);
            boolean hasMatches = !pdfMatches.isEmpty();
            List<RedactionMatch> approved = new ArrayList<>();
            for (RedactionMatch m : pdfMatches) {
                approved.add(m.withSelection(true));
            }
            RedactionResult redRes = docService.applyApprovedRedactions(samplePdf, approved);
            boolean redactOk = redRes.isSuccess() && redRes.getApprovedMatchesApplied() > 0;
            if (redRes.isSuccess()) {
                Files.deleteIfExists(redRes.getOutputPath());
            }
            if (fmt == DocumentFormat.PDF && redactionSupported && hasMatches && redactOk) {
                System.out.println("PASSED (PDF scan and content stream redaction operational: " + pdfMatches.size() + " matches)");
                passed++;
            } else {
                System.out.println("FAILED (redactionSupported=" + redactionSupported + ", matches=" + pdfMatches.size() + ", redactOk=" + redactOk + ")");
                failed++;
            }

            // Cleanup
            Files.deleteIfExists(sampleFile);
            Files.deleteIfExists(redactedFile);
            Files.deleteIfExists(sigFile);

        } catch (Exception e) {
            System.err.println("Test error: " + e.getMessage());
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
