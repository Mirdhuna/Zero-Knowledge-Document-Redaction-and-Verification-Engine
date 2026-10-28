package com.zeroknowledge.model;

import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Metadata and public details for cryptographic keys.
 * Never stores or exposes raw private key contents.
 */
public class KeyInfo {
    private final String alias;
    private final String algorithm;
    private final int keySizeBits;
    private final long createdAtEpochMs;
    private final String fingerprintSha256;
    private final String publicKeyPem;
    private final boolean privateKeyAvailable;

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public KeyInfo(String alias, String algorithm, int keySizeBits, long createdAtEpochMs,
                   String fingerprintSha256, String publicKeyPem, boolean privateKeyAvailable) {
        this.alias = alias;
        this.algorithm = algorithm;
        this.keySizeBits = keySizeBits;
        this.createdAtEpochMs = createdAtEpochMs;
        this.fingerprintSha256 = fingerprintSha256;
        this.publicKeyPem = publicKeyPem;
        this.privateKeyAvailable = privateKeyAvailable;
    }

    public String getAlias() {
        return alias;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeySizeBits() {
        return keySizeBits;
    }

    public long getCreatedAtEpochMs() {
        return createdAtEpochMs;
    }

    public String getFormattedCreatedAt() {
        return FORMATTER.format(Instant.ofEpochMilli(createdAtEpochMs));
    }

    public String getFingerprintSha256() {
        return fingerprintSha256;
    }

    public String getPublicKeyPem() {
        return publicKeyPem;
    }

    public boolean isPrivateKeyAvailable() {
        return privateKeyAvailable;
    }

    @Override
    public String toString() {
        return alias + " (" + algorithm + " " + keySizeBits + "-bit, " +
                (fingerprintSha256.length() > 16 ? fingerprintSha256.substring(0, 16) + "..." : fingerprintSha256) + ")";
    }
}
