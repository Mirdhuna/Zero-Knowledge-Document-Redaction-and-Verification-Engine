package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.AccessControlService;
import com.zeroknowledge.backend.DocumentService;
import com.zeroknowledge.backend.RedactionService;
import com.zeroknowledge.backend.SensitiveDataDetector;
import com.zeroknowledge.backend.VerificationService;
import com.zeroknowledge.crypto.HashService;
import com.zeroknowledge.crypto.KeyManager;
import com.zeroknowledge.crypto.SignatureService;
import com.zeroknowledge.storage.ApplicationConfig;
import com.zeroknowledge.storage.AuditService;
import com.zeroknowledge.storage.FileStorageService;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Dependency-injection container holding instances of the official backend services.
 * Injected into Swing views via constructors.
 */
public class BackendContext {

    private final ApplicationConfig applicationConfig;
    private final FileStorageService fileStorageService;
    private final HashService hashService;
    private final KeyManager keyManager;
    private final SignatureService signatureService;
    private final AuditService auditService;
    private final AccessControlService accessControlService;
    private final DocumentService documentService;
    private final VerificationService verificationService;

    // In-memory key session store for UI convenience
    private final Map<String, KeyPair> sessionKeyPairs = new LinkedHashMap<>();
    private final Map<String, PublicKey> knownPublicKeys = new LinkedHashMap<>();
    private String activeKeyAlias = null;

    public BackendContext() {
        this.applicationConfig = ApplicationConfig.createDefault();
        this.auditService = new AuditService(applicationConfig);
        this.accessControlService = new AccessControlService(
                AccessControlService.Role.SECURITY_ADMINISTRATOR, auditService);
        this.hashService = new HashService();
        this.fileStorageService = new FileStorageService(applicationConfig, hashService);
        this.keyManager = new KeyManager(hashService);
        this.signatureService = new SignatureService(hashService, keyManager);

        RedactionService redactionService = new RedactionService(
                fileStorageService, hashService, accessControlService, auditService);

        this.documentService = new DocumentService(
                fileStorageService,
                new SensitiveDataDetector(),
                redactionService,
                accessControlService,
                auditService);

        this.verificationService = new VerificationService(
                hashService,
                keyManager,
                signatureService,
                accessControlService,
                auditService);

        // Generate an initial default 3072-bit RSA key pair for the session
        try {
            KeyPair defaultKey = keyManager.generateKeyPair(3072);
            String alias = "admin-rsa-3072";
            sessionKeyPairs.put(alias, defaultKey);
            knownPublicKeys.put(alias, defaultKey.getPublic());
            this.activeKeyAlias = alias;
        } catch (Exception e) {
            System.err.println("Note: Default key generation skipped: " + e.getMessage());
        }
    }

    public ApplicationConfig getApplicationConfig() {
        return applicationConfig;
    }

    public FileStorageService getFileStorageService() {
        return fileStorageService;
    }

    public HashService getHashService() {
        return hashService;
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }

    public SignatureService getSignatureService() {
        return signatureService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public AccessControlService getAccessControlService() {
        return accessControlService;
    }

    public DocumentService getDocumentService() {
        return documentService;
    }

    public VerificationService getVerificationService() {
        return verificationService;
    }

    // Key session helpers
    public synchronized Map<String, KeyPair> getSessionKeyPairs() {
        return new LinkedHashMap<>(sessionKeyPairs);
    }

    public synchronized Map<String, PublicKey> getKnownPublicKeys() {
        return new LinkedHashMap<>(knownPublicKeys);
    }

    public synchronized void registerKeyPair(String alias, KeyPair keyPair) {
        sessionKeyPairs.put(alias, keyPair);
        knownPublicKeys.put(alias, keyPair.getPublic());
        if (activeKeyAlias == null) {
            activeKeyAlias = alias;
        }
    }

    public synchronized void registerPublicKey(String alias, PublicKey publicKey) {
        knownPublicKeys.put(alias, publicKey);
    }

    public synchronized KeyPair getActiveKeyPair() {
        if (activeKeyAlias == null) return null;
        return sessionKeyPairs.get(activeKeyAlias);
    }

    public synchronized String getActiveKeyAlias() {
        return activeKeyAlias;
    }

    public synchronized void setActiveKeyAlias(String activeKeyAlias) {
        this.activeKeyAlias = activeKeyAlias;
    }
}
