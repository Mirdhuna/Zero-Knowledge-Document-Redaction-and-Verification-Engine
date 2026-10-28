package com.zeroknowledge.backend;

import com.zeroknowledge.model.KeyInfo;
import com.zeroknowledge.model.VerificationResult;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Backend service for cryptographic operations:
 * - SHA-256 digest computation
 * - RSA key pair generation (2048, 3072, 4096 bits)
 * - Detached digital signatures (SHA256withRSA)
 * - Cryptographic signature verification
 * - Public key export and import (X.509 PEM)
 */
public class CryptoService {

    private final Map<String, KeyPair> activeKeyPairs = new LinkedHashMap<>();
    private final Map<String, KeyInfo> activeKeyInfos = new LinkedHashMap<>();
    private String currentSelectedAlias = null;

    public CryptoService() {
        // Initialize an active key pair so user has one ready out of the box if desired
        try {
            generateKeyPair(2048, "default-rsa-key");
        } catch (Exception e) {
            // Log warning internally
            System.err.println("Warning: Default RSA key generation failed: " + e.getMessage());
        }
    }

    /**
     * Computes the SHA-256 digest of a file.
     */
    public String calculateSha256(File file) throws IOException, NoSuchAlgorithmException {
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("File not found for SHA-256 computation.");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return bytesToHex(digest.digest());
    }

    /**
     * Generates a new RSA key pair of the specified size.
     */
    public synchronized KeyInfo generateKeyPair(int keySizeBits, String alias)
            throws NoSuchAlgorithmException {
        if (keySizeBits != 2048 && keySizeBits != 3072 && keySizeBits != 4096) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + keySizeBits + ". Use 2048, 3072, or 4096 bits.");
        }

        if (alias == null || alias.trim().isEmpty()) {
            alias = "rsa-" + keySizeBits + "-" + (System.currentTimeMillis() % 10000);
        }
        alias = alias.trim();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySizeBits, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        String pem = encodePublicKeyToPem(keyPair.getPublic());
        String fingerprint = computeKeyFingerprint(keyPair.getPublic());

        KeyInfo info = new KeyInfo(
                alias,
                "RSA",
                keySizeBits,
                System.currentTimeMillis(),
                fingerprint,
                pem,
                true
        );

        activeKeyPairs.put(alias, keyPair);
        activeKeyInfos.put(alias, info);
        currentSelectedAlias = alias;

        return info;
    }

    /**
     * Signs a document using SHA256withRSA and writes a detached signature file.
     */
    public void signDocument(File documentFile, PrivateKey privateKey, File outputSignatureFile)
            throws Exception {
        if (documentFile == null || !documentFile.exists()) {
            throw new FileNotFoundException("Document file to sign does not exist.");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key is required for signing.");
        }
        if (outputSignatureFile == null) {
            throw new IllegalArgumentException("Output signature file cannot be null.");
        }

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        rsaSign.initSign(privateKey);

        try (InputStream is = new BufferedInputStream(new FileInputStream(documentFile))) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                rsaSign.update(buffer, 0, read);
            }
        }

        byte[] signatureBytes = rsaSign.sign();
        // Save as Base64 encoded format with metadata header for transparency and portability
        String base64Sig = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(signatureBytes);
        String signaturePayload = "-----BEGIN DETACHED SIGNATURE-----\n" +
                base64Sig + "\n" +
                "-----END DETACHED SIGNATURE-----\n";

        File parent = outputSignatureFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        Files.writeString(outputSignatureFile.toPath(), signaturePayload, StandardCharsets.UTF_8);
    }

    /**
     * Verifies a document against a detached signature file and a public key.
     */
    public VerificationResult verifySignature(File documentFile, File signatureFile, PublicKey publicKey) {
        long startTime = System.currentTimeMillis();

        if (documentFile == null || !documentFile.exists()) {
            return VerificationResult.create(
                    VerificationResult.Status.VERIFICATION_ERROR,
                    documentFile != null ? documentFile.getAbsolutePath() : "",
                    signatureFile != null ? signatureFile.getAbsolutePath() : "",
                    "-", "-", "-",
                    "Document file not found or inaccessible.",
                    System.currentTimeMillis() - startTime
            );
        }

        if (signatureFile == null || !signatureFile.exists()) {
            return VerificationResult.create(
                    VerificationResult.Status.SIGNATURE_MISSING_OR_INVALID,
                    documentFile.getAbsolutePath(),
                    signatureFile != null ? signatureFile.getAbsolutePath() : "",
                    "-", "-", "-",
                    "Detached signature file not found or not specified.",
                    System.currentTimeMillis() - startTime
            );
        }

        if (publicKey == null) {
            return VerificationResult.create(
                    VerificationResult.Status.TRUSTED_PUBLIC_KEY_UNAVAILABLE,
                    documentFile.getAbsolutePath(),
                    signatureFile.getAbsolutePath(),
                    "-", "-", "-",
                    "No valid public key available for signature verification.",
                    System.currentTimeMillis() - startTime
            );
        }

        String computedSha256;
        try {
            computedSha256 = calculateSha256(documentFile);
        } catch (Exception e) {
            return VerificationResult.create(
                    VerificationResult.Status.VERIFICATION_ERROR,
                    documentFile.getAbsolutePath(),
                    signatureFile.getAbsolutePath(),
                    "-", "-", "-",
                    "Failed to compute document hash: " + e.getMessage(),
                    System.currentTimeMillis() - startTime
            );
        }

        String keyFingerprint = computeKeyFingerprint(publicKey);
        String keyAlgorithm = publicKey.getAlgorithm();

        byte[] rawSignatureBytes;
        try {
            String sigContent = Files.readString(signatureFile.toPath(), StandardCharsets.UTF_8).trim();
            if (sigContent.contains("BEGIN DETACHED SIGNATURE")) {
                sigContent = sigContent.replace("-----BEGIN DETACHED SIGNATURE-----", "")
                        .replace("-----END DETACHED SIGNATURE-----", "")
                        .replaceAll("\\s+", "");
                rawSignatureBytes = Base64.getDecoder().decode(sigContent);
            } else {
                // Try direct binary read if not base64 text
                rawSignatureBytes = Files.readAllBytes(signatureFile.toPath());
            }
        } catch (Exception e) {
            return VerificationResult.create(
                    VerificationResult.Status.SIGNATURE_MISSING_OR_INVALID,
                    documentFile.getAbsolutePath(),
                    signatureFile.getAbsolutePath(),
                    keyFingerprint, keyAlgorithm, computedSha256,
                    "Could not decode signature file content: " + e.getMessage(),
                    System.currentTimeMillis() - startTime
            );
        }

        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);

            try (InputStream is = new BufferedInputStream(new FileInputStream(documentFile))) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    verifier.update(buffer, 0, read);
                }
            }

            boolean matches = verifier.verify(rawSignatureBytes);
            long duration = System.currentTimeMillis() - startTime;

            if (matches) {
                return VerificationResult.create(
                        VerificationResult.Status.SIGNATURE_VALID,
                        documentFile.getAbsolutePath(),
                        signatureFile.getAbsolutePath(),
                        keyFingerprint, keyAlgorithm, computedSha256,
                        "Cryptographic signature is valid. The document has not been altered since it was signed with the corresponding private key.",
                        duration
                );
            } else {
                return VerificationResult.create(
                        VerificationResult.Status.DOCUMENT_MODIFIED_OR_MISMATCH,
                        documentFile.getAbsolutePath(),
                        signatureFile.getAbsolutePath(),
                        keyFingerprint, keyAlgorithm, computedSha256,
                        "Signature verification failed: Either the document content was modified after signing, or the signature was generated with a different cryptographic key.",
                        duration
                );
            }
        } catch (SignatureException se) {
            return VerificationResult.create(
                    VerificationResult.Status.DOCUMENT_MODIFIED_OR_MISMATCH,
                    documentFile.getAbsolutePath(),
                    signatureFile.getAbsolutePath(),
                    keyFingerprint, keyAlgorithm, computedSha256,
                    "Signature mismatch or malformed signature: " + se.getMessage(),
                    System.currentTimeMillis() - startTime
            );
        } catch (Exception e) {
            return VerificationResult.create(
                    VerificationResult.Status.VERIFICATION_ERROR,
                    documentFile.getAbsolutePath(),
                    signatureFile.getAbsolutePath(),
                    keyFingerprint, keyAlgorithm, computedSha256,
                    "Cryptographic verification error: " + e.getMessage(),
                    System.currentTimeMillis() - startTime
            );
        }
    }

    /**
     * Exports a public key to an X.509 PEM formatted file.
     */
    public void exportPublicKeyToPemFile(PublicKey publicKey, File destination) throws IOException {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null.");
        }
        if (destination == null) {
            throw new IllegalArgumentException("Destination file cannot be null.");
        }

        File parent = destination.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        String pem = encodePublicKeyToPem(publicKey);
        Files.writeString(destination.toPath(), pem, StandardCharsets.UTF_8);
    }

    /**
     * Loads a public key from an X.509 PEM file.
     */
    public PublicKey loadPublicKeyFromPemFile(File pemFile) throws Exception {
        if (pemFile == null || !pemFile.exists()) {
            throw new FileNotFoundException("PEM file does not exist: " + (pemFile != null ? pemFile.getPath() : ""));
        }

        String content = Files.readString(pemFile.toPath(), StandardCharsets.UTF_8);
        String cleaned = content.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(keySpec);

        String alias = pemFile.getName().replace(".pem", "").replace(".pub", "");
        String fingerprint = computeKeyFingerprint(pk);
        KeyInfo info = new KeyInfo(alias, "RSA", 2048, System.currentTimeMillis(), fingerprint, encodePublicKeyToPem(pk), false);

        activeKeyInfos.put(alias, info);
        return pk;
    }

    public String encodePublicKeyToPem(PublicKey publicKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    public String computeKeyFingerprint(PublicKey publicKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(publicKey.getEncoded());
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return "UNKNOWN";
        }
    }

    public synchronized List<KeyInfo> getAvailableKeyInfos() {
        return new ArrayList<>(activeKeyInfos.values());
    }

    public synchronized KeyPair getKeyPair(String alias) {
        return activeKeyPairs.get(alias);
    }

    public synchronized KeyInfo getKeyInfo(String alias) {
        return activeKeyInfos.get(alias);
    }

    public synchronized String getSelectedAlias() {
        return currentSelectedAlias;
    }

    public synchronized void setSelectedAlias(String alias) {
        if (activeKeyInfos.containsKey(alias)) {
            this.currentSelectedAlias = alias;
        }
    }

    public synchronized KeyPair getActiveKeyPair() {
        if (currentSelectedAlias == null) return null;
        return activeKeyPairs.get(currentSelectedAlias);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
