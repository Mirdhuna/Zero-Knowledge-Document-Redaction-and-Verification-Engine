package com.zeroknowledge.crypto;

import com.zeroknowledge.exception.KeyManagementException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages RSA key-pair generation, key identifiers, public-key export/loading,
 * and password-based authenticated encryption for local private-key storage.
 *
 * <h3>Security Architecture & Limitations</h3>
 * <ul>
 *   <li>Defaults to 3072-bit RSA keys (minimum enforced: 2048-bit).</li>
 *   <li>Never uses Java object serialization ({@code ObjectOutputStream}) for keys.</li>
 *   <li>Public keys are exported as X.509 SubjectPublicKeyInfo PEM files.</li>
 *   <li>Private keys saved to disk are encrypted using {@code PBKDF2WithHmacSHA256} (210,000 iterations,
 *       128-bit random salt) and {@code AES/GCM/NoPadding} (256-bit key, 96-bit IV, 128-bit authentication tag).</li>
 *   <li><strong>Limitation:</strong> Standard JDK APIs without hardware security modules (HSM) or OS native
 *       keychain JNI bridges cannot prevent an attacker with local OS root/debugger access from reading process memory,
 *       nor prevent offline dictionary attacks if a user chooses a weak passphrase.</li>
 * </ul>
 */
public final class KeyManager {

    public static final String KEY_ALGORITHM = "RSA";
    public static final int DEFAULT_KEY_SIZE = 3072;
    public static final int MIN_KEY_SIZE = 2048;
    public static final int MAX_KEY_SIZE = 8192;

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int AES_KEY_BITS = 256;
    private static final String KEYSTORE_FORMAT_VERSION = "ZK-ENCKEY-1.0";

    private static final String PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";

    private final HashService hashService;
    private final SecureRandom secureRandom;

    public KeyManager(HashService hashService) {
        this.hashService = Objects.requireNonNull(hashService, "hashService must not be null");
        this.secureRandom = new SecureRandom();
    }

    public KeyManager() {
        this(new HashService());
    }

    /**
     * Generates a new RSA {@link KeyPair} using the default 3072-bit key size.
     */
    public KeyPair generateKeyPair() throws KeyManagementException {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }

    /**
     * Generates a new RSA {@link KeyPair} with the specified key size in bits.
     *
     * @param keySizeBits RSA modulus size in bits (must be between 2048 and 8192)
     */
    public KeyPair generateKeyPair(int keySizeBits) throws KeyManagementException {
        if (keySizeBits < MIN_KEY_SIZE || keySizeBits > MAX_KEY_SIZE) {
            throw new KeyManagementException(
                    "Invalid RSA key size: " + keySizeBits + " bits. Allowed range: "
                            + MIN_KEY_SIZE + " to " + MAX_KEY_SIZE + " bits.");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            generator.initialize(keySizeBits, secureRandom);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new KeyManagementException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Computes a deterministic, collision-resistant key identifier from a {@link PublicKey}.
     * Format: {@code SHA256:<first-16-hex-chars-of-SPKI-digest>} (64 bits of prefix entropy for display,
     * backed by full SPKI validation).
     */
    public String getKeyIdentifier(PublicKey publicKey) throws KeyManagementException {
        validatePublicKey(publicKey);
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new KeyManagementException("Public key does not support standard X.509 encoding");
        }
        String fullHash = hashService.calculateSha256(encoded);
        return "SHA256:" + fullHash.substring(0, 16);
    }

    /**
     * Computes the full 64-character hexadecimal SHA-256 fingerprint of a {@link PublicKey}.
     */
    public String getFullKeyFingerprint(PublicKey publicKey) throws KeyManagementException {
        validatePublicKey(publicKey);
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new KeyManagementException("Public key does not support standard X.509 encoding");
        }
        return hashService.calculateSha256(encoded);
    }

    /**
     * Validates that a {@link PublicKey} is a non-null RSA key meeting minimum modulus length requirements.
     */
    public void validatePublicKey(PublicKey publicKey) throws KeyManagementException {
        if (publicKey == null) {
            throw new KeyManagementException("Public key is null");
        }
        if (!KEY_ALGORITHM.equalsIgnoreCase(publicKey.getAlgorithm())) {
            throw new KeyManagementException("Unsupported public key algorithm: " + publicKey.getAlgorithm());
        }
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            int bitLength = rsaPublicKey.getModulus().bitLength();
            if (bitLength < MIN_KEY_SIZE) {
                throw new KeyManagementException(
                        "RSA public key modulus is too weak (" + bitLength + " bits; minimum is " + MIN_KEY_SIZE + ")");
            }
        } else {
            throw new KeyManagementException("Public key is not an instance of RSAPublicKey");
        }
    }

    /**
     * Validates that a {@link PrivateKey} is a non-null RSA private key meeting minimum modulus length requirements.
     */
    public void validatePrivateKey(PrivateKey privateKey) throws KeyManagementException {
        if (privateKey == null) {
            throw new KeyManagementException("Private key is null");
        }
        if (!KEY_ALGORITHM.equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new KeyManagementException("Unsupported private key algorithm: " + privateKey.getAlgorithm());
        }
        if (privateKey instanceof RSAPrivateKey rsaPrivateKey) {
            int bitLength = rsaPrivateKey.getModulus().bitLength();
            if (bitLength < MIN_KEY_SIZE) {
                throw new KeyManagementException(
                        "RSA private key modulus is too weak (" + bitLength + " bits; minimum is " + MIN_KEY_SIZE + ")");
            }
        }
    }

    /**
     * Exports an RSA {@link PublicKey} to a standard X.509 PEM file.
     */
    public void exportPublicKey(PublicKey publicKey, Path destinationPath) throws KeyManagementException {
        validatePublicKey(publicKey);
        Objects.requireNonNull(destinationPath, "destinationPath must not be null");
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null) {
            throw new KeyManagementException("Unable to encode public key to X.509 format");
        }

        String base64Body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(encoded);
        String pemContent = PUBLIC_KEY_PEM_HEADER + "\n" + base64Body + "\n" + PUBLIC_KEY_PEM_FOOTER + "\n";

        writeFileAtomically(destinationPath, pemContent);
    }

    /**
     * Loads and validates an RSA {@link PublicKey} from an X.509 PEM or Base64 file.
     */
    public PublicKey loadPublicKey(Path publicKeyPath) throws KeyManagementException {
        Objects.requireNonNull(publicKeyPath, "publicKeyPath must not be null");
        Path normalized = publicKeyPath.toAbsolutePath().normalize();
        if (!Files.exists(normalized) || !Files.isRegularFile(normalized)) {
            throw new KeyManagementException("Public key file does not exist: " + normalized.getFileName());
        }
        try {
            long size = Files.size(normalized);
            if (size == 0 || size > 64 * 1024) {
                throw new KeyManagementException("Public key file has invalid size: " + normalized.getFileName());
            }
            String rawContent = Files.readString(normalized, StandardCharsets.UTF_8);
            return parsePublicKeyPem(rawContent);
        } catch (IOException e) {
            throw new KeyManagementException("Failed to read public key file: " + normalized.getFileName(), e);
        }
    }

    /**
     * Parses and validates an RSA {@link PublicKey} from a PEM string.
     */
    public PublicKey parsePublicKeyPem(String pemContent) throws KeyManagementException {
        if (pemContent == null || pemContent.isBlank()) {
            throw new KeyManagementException("Public key content is empty");
        }
        String cleaned = pemContent
                .replace(PUBLIC_KEY_PEM_HEADER, "")
                .replace(PUBLIC_KEY_PEM_FOOTER, "")
                .replaceAll("\\s+", "");

        if (cleaned.isEmpty()) {
            throw new KeyManagementException("Public key PEM contains no Base64 payload");
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(cleaned);
        } catch (IllegalArgumentException e) {
            throw new KeyManagementException("Public key is not valid Base64", e);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
            validatePublicKey(publicKey);
            return publicKey;
        } catch (GeneralSecurityException e) {
            throw new KeyManagementException("Invalid X.509 RSA public key structure", e);
        }
    }

    /**
     * Encrypts and stores an RSA {@link PrivateKey} (with its associated public key ID) to a local file
     * using PBKDF2-HMAC-SHA256 and AES-256-GCM authenticated encryption.
     *
     * @param privateKey      the RSA private key to protect
     * @param publicKey       the corresponding RSA public key (for key identifier metadata)
     * @param passphrase      non-empty passphrase characters (caller may zeroize array after call)
     * @param destinationPath path to write the encrypted key bundle
     */
    public void saveEncryptedPrivateKey(
            PrivateKey privateKey,
            PublicKey publicKey,
            char[] passphrase,
            Path destinationPath) throws KeyManagementException {
        validatePrivateKey(privateKey);
        validatePublicKey(publicKey);
        validatePassphrase(passphrase);
        Objects.requireNonNull(destinationPath, "destinationPath must not be null");

        byte[] pkcs8Bytes = privateKey.getEncoded();
        if (pkcs8Bytes == null || pkcs8Bytes.length == 0) {
            throw new KeyManagementException("Private key does not support PKCS#8 encoding");
        }

        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[GCM_IV_BYTES];
        secureRandom.nextBytes(salt);
        secureRandom.nextBytes(iv);

        String keyId = getKeyIdentifier(publicKey);
        byte[] aad = (KEYSTORE_FORMAT_VERSION + "|" + keyId).getBytes(StandardCharsets.UTF_8);

        try {
            SecretKey aesKey = deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(pkcs8Bytes);

            Properties props = new Properties();
            props.setProperty("version", KEYSTORE_FORMAT_VERSION);
            props.setProperty("kdf", PBKDF2_ALGORITHM);
            props.setProperty("iterations", Integer.toString(PBKDF2_ITERATIONS));
            props.setProperty("cipher", CIPHER_ALGORITHM);
            props.setProperty("keyId", keyId);
            props.setProperty("createdAt", Instant.now().toString());
            props.setProperty("saltBase64", Base64.getEncoder().encodeToString(salt));
            props.setProperty("ivBase64", Base64.getEncoder().encodeToString(iv));
            props.setProperty("ciphertextBase64", Base64.getEncoder().encodeToString(ciphertext));

            try (StringWriter writer = new StringWriter()) {
                props.store(writer, "Zero-Knowledge Encrypted Private Key Store");
                writeFileAtomically(destinationPath, writer.toString());
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new KeyManagementException("Failed to encrypt and save private key", e);
        } finally {
            Arrays.fill(pkcs8Bytes, (byte) 0);
        }
    }

    /**
     * Loads and decrypts an RSA {@link PrivateKey} from an encrypted local key bundle.
     *
     * @param encryptedKeyPath path to the encrypted private key file
     * @param passphrase       passphrase used when saving the key
     * @return decrypted {@link PrivateKey}
     * @throws KeyManagementException if the file is missing, corrupted, or the passphrase is incorrect
     */
    public PrivateKey loadEncryptedPrivateKey(Path encryptedKeyPath, char[] passphrase)
            throws KeyManagementException {
        Objects.requireNonNull(encryptedKeyPath, "encryptedKeyPath must not be null");
        validatePassphrase(passphrase);

        Path normalized = encryptedKeyPath.toAbsolutePath().normalize();
        if (!Files.exists(normalized) || !Files.isRegularFile(normalized)) {
            throw new KeyManagementException("Encrypted private key file does not exist: " + normalized.getFileName());
        }

        Properties props = new Properties();
        try {
            String content = Files.readString(normalized, StandardCharsets.UTF_8);
            try (Reader reader = new StringReader(content)) {
                props.load(reader);
            }
        } catch (IOException | IllegalArgumentException e) {
            throw new KeyManagementException(
                    "Unable to read encrypted private key file: " + normalized.getFileName(), e);
        }

        String version = props.getProperty("version");
        if (!KEYSTORE_FORMAT_VERSION.equals(version)) {
            throw new KeyManagementException("Unsupported encrypted key format version");
        }

        String keyId = props.getProperty("keyId");
        String iterationsStr = props.getProperty("iterations");
        String saltB64 = props.getProperty("saltBase64");
        String ivB64 = props.getProperty("ivBase64");
        String ciphertextB64 = props.getProperty("ciphertextBase64");

        if (keyId == null || iterationsStr == null || saltB64 == null || ivB64 == null || ciphertextB64 == null) {
            throw new KeyManagementException("Encrypted private key file is missing required fields");
        }

        int iterations;
        byte[] salt;
        byte[] iv;
        byte[] ciphertext;
        try {
            iterations = Integer.parseInt(iterationsStr.trim());
            if (iterations < 10_000 || iterations > 5_000_000) {
                throw new KeyManagementException("Invalid PBKDF2 iteration count in key file");
            }
            salt = Base64.getDecoder().decode(saltB64.trim());
            iv = Base64.getDecoder().decode(ivB64.trim());
            ciphertext = Base64.getDecoder().decode(ciphertextB64.trim());
        } catch (IllegalArgumentException e) {
            throw new KeyManagementException("Corrupted Base64 or numeric parameters in encrypted key file", e);
        }

        byte[] aad = (KEYSTORE_FORMAT_VERSION + "|" + keyId.trim()).getBytes(StandardCharsets.UTF_8);
        byte[] pkcs8Bytes = null;
        try {
            SecretKey aesKey = deriveAesKey(passphrase, salt, iterations);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            cipher.updateAAD(aad);
            pkcs8Bytes = cipher.doFinal(ciphertext);

            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
            validatePrivateKey(privateKey);
            return privateKey;
        } catch (GeneralSecurityException e) {
            throw new KeyManagementException("Private key decryption failed (incorrect passphrase or tampered key file)", e);
        } finally {
            if (pkcs8Bytes != null) {
                Arrays.fill(pkcs8Bytes, (byte) 0);
            }
        }
    }

    private static void validatePassphrase(char[] passphrase) throws KeyManagementException {
        if (passphrase == null || passphrase.length < 8) {
            throw new KeyManagementException("Passphrase must be at least 8 characters long");
        }
    }

    private static SecretKey deriveAesKey(char[] passphrase, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, AES_KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] encoded = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(encoded, "AES");
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    private static void writeFileAtomically(Path destinationPath, String content) throws KeyManagementException {
        Path normalized = destinationPath.toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tempFile = Files.createTempFile(parent != null ? parent : Path.of("."), "zkkey_", ".tmp");
            try {
                Files.writeString(tempFile, content, StandardCharsets.UTF_8);
                Files.move(tempFile, normalized, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException moveEx) {
                Files.move(tempFile, normalized, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tempFile);
            }
        } catch (IOException e) {
            throw new KeyManagementException("Failed to write key file: " + normalized.getFileName(), e);
        }
    }
}
