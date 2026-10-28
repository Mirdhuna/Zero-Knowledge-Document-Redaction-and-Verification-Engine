package com.zeroknowledge.backend;

import com.zeroknowledge.model.OperationRecord.OperationType;
import com.zeroknowledge.storage.AuditService;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Backend access-control service enforcing separation between ordinary document processing
 * and privileged cryptographic operations (private-key management and signing).
 *
 * <h3>Security Model & Limitations</h3>
 * <p>This is an in-process role-based capability gate for a local desktop application.
 * It prevents unauthorized UI flows or unprivileged roles (e.g. {@link Role#AUDITOR_VERIFIER} or
 * {@link Role#REDACTION_OPERATOR}) from invoking private-key generation or signing APIs unless
 * explicitly elevated. As documented in {@code SECURITY.md}, a local desktop process running under a single
 * OS user account cannot enforce multi-user cryptographic isolation against a user who controls the JVM
 * unless private keys are encrypted with a passphrase known only to the key holder (which {@code KeyManager} enforces).
 */
public final class AccessControlService {

    /**
     * Granular permissions enforced by the backend services.
     */
    public enum Permission {
        SCAN_DOCUMENT,
        REDACT_DOCUMENT,
        CALCULATE_HASH,
        VERIFY_SIGNATURE,
        EXPORT_OR_LOAD_PUBLIC_KEY,
        GENERATE_KEY_PAIR,
        MANAGE_PRIVATE_KEY,
        SIGN_DOCUMENT,
        VIEW_AUDIT_LOG
    }

    /**
     * Built-in role profiles separating redaction, verification, and cryptographic signing duties.
     */
    public enum Role {
        /** Can only hash files, load public keys, verify signatures, and view audit logs. */
        AUDITOR_VERIFIER(EnumSet.of(
                Permission.CALCULATE_HASH,
                Permission.VERIFY_SIGNATURE,
                Permission.EXPORT_OR_LOAD_PUBLIC_KEY,
                Permission.VIEW_AUDIT_LOG)),

        /** Can scan and redact documents, hash files, and verify signatures, but CANNOT manage private keys or sign. */
        REDACTION_OPERATOR(EnumSet.of(
                Permission.SCAN_DOCUMENT,
                Permission.REDACT_DOCUMENT,
                Permission.CALCULATE_HASH,
                Permission.VERIFY_SIGNATURE,
                Permission.EXPORT_OR_LOAD_PUBLIC_KEY,
                Permission.VIEW_AUDIT_LOG)),

        /** Full authorization including RSA key generation, private-key management, and artifact signing. */
        SECURITY_ADMINISTRATOR(EnumSet.allOf(Permission.class));

        private final Set<Permission> permissions;

        Role(Set<Permission> permissions) {
            this.permissions = Collections.unmodifiableSet(EnumSet.copyOf(permissions));
        }

        public Set<Permission> getPermissions() {
            return permissions;
        }

        public boolean hasPermission(Permission permission) {
            return permissions.contains(permission);
        }
    }

    private final AtomicReference<Role> activeRole;
    private final AuditService auditService;

    public AccessControlService(Role initialRole, AuditService auditService) {
        this.activeRole = new AtomicReference<>(Objects.requireNonNull(initialRole, "initialRole must not be null"));
        this.auditService = Objects.requireNonNull(auditService, "auditService must not be null");
    }

    public AccessControlService() {
        this(Role.SECURITY_ADMINISTRATOR, new AuditService());
    }

    /**
     * Returns the currently active role.
     */
    public Role getActiveRole() {
        return activeRole.get();
    }

    /**
     * Updates the active role and records the transition in the audit log.
     */
    public void setActiveRole(Role newRole) {
        Objects.requireNonNull(newRole, "newRole must not be null");
        Role previous = activeRole.getAndSet(newRole);
        auditService.record(
                OperationType.ACCESS_CHECK,
                "ROLE_CHANGE",
                true,
                "Active role changed from " + previous.name() + " to " + newRole.name());
    }

    /**
     * Checks whether the specified permission is granted to the currently active role.
     */
    public boolean isPermitted(Permission permission) {
        Objects.requireNonNull(permission, "permission must not be null");
        Role role = activeRole.get();
        boolean allowed = role.hasPermission(permission);
        if (!allowed) {
            auditService.record(
                    OperationType.ACCESS_CHECK,
                    permission.name(),
                    false,
                    "Permission " + permission.name() + " denied for role " + role.name());
        }
        return allowed;
    }

    /**
     * Enforces that the active role holds {@code permission}, throwing {@link SecurityException} if denied.
     */
    public void requirePermission(Permission permission) throws SecurityException {
        if (!isPermitted(permission)) {
            throw new SecurityException(
                    "Access denied: active role " + activeRole.get().name()
                            + " does not have permission " + permission.name());
        }
    }
}
