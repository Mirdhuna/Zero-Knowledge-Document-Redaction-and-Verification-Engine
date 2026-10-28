package com.zeroknowledge.backend;

/**
 * Dependency injection container holding the core backend service instances.
 * Injected into frontend panels via constructors.
 */
public class BackendContext {
    private final RedactionService redactionService;
    private final CryptoService cryptoService;
    private final AuditService auditService;
    private final ConfigService configService;

    public BackendContext() {
        this.configService = new ConfigService();
        this.auditService = new AuditService();
        this.cryptoService = new CryptoService();
        this.redactionService = new RedactionService();
    }

    public BackendContext(RedactionService redactionService,
                          CryptoService cryptoService,
                          AuditService auditService,
                          ConfigService configService) {
        this.redactionService = redactionService;
        this.cryptoService = cryptoService;
        this.auditService = auditService;
        this.configService = configService;
    }

    public RedactionService getRedactionService() {
        return redactionService;
    }

    public CryptoService getCryptoService() {
        return cryptoService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public ConfigService getConfigService() {
        return configService;
    }
}
