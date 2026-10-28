package com.zeroknowledge.backend;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Backend service for managing user configuration and preferences.
 * Persists via standard Java Properties without external databases or frameworks.
 */
public class ConfigService {

    private final File configFile;
    private final Properties properties = new Properties();

    private static final String KEY_OUTPUT_DIR = "app.output.directory";
    private static final String KEY_KEY_DIR = "app.keys.directory";
    private static final String KEY_PATTERNS = "app.detection.patterns";

    public ConfigService() {
        File home = new File(System.getProperty("user.home"));
        File baseDir = (home.exists() && home.canWrite()) ? home : new File(System.getProperty("user.dir"));
        this.configFile = new File(baseDir, ".zk_redaction_config.properties");
        loadDefaults();
        loadFromDisk();
    }

    private void loadDefaults() {
        String defaultOutput = new File(System.getProperty("user.home"), "Redacted_Documents").getAbsolutePath();
        String defaultKeys = new File(System.getProperty("user.home"), ".zk_keys").getAbsolutePath();

        properties.setProperty(KEY_OUTPUT_DIR, defaultOutput);
        properties.setProperty(KEY_KEY_DIR, defaultKeys);
        properties.setProperty(KEY_PATTERNS, "EMAIL,SSN,CREDIT_CARD,PHONE,API_KEY,IP_ADDRESS");
    }

    public synchronized void loadFromDisk() {
        if (!configFile.exists()) {
            saveToDisk();
            return;
        }
        try (InputStream in = new FileInputStream(configFile)) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            System.err.println("Warning: could not load config file: " + e.getMessage());
        }
    }

    public synchronized void saveToDisk() {
        try (OutputStream out = new FileOutputStream(configFile)) {
            properties.store(new OutputStreamWriter(out, StandardCharsets.UTF_8),
                    "Zero-Knowledge Redaction & Verification Engine Configuration");
        } catch (IOException e) {
            System.err.println("Warning: could not save config file: " + e.getMessage());
        }
    }

    public synchronized String getOutputDirectory() {
        return properties.getProperty(KEY_OUTPUT_DIR);
    }

    public synchronized void setOutputDirectory(String dirPath) {
        if (dirPath != null && !dirPath.trim().isEmpty()) {
            properties.setProperty(KEY_OUTPUT_DIR, dirPath.trim());
            saveToDisk();
        }
    }

    public synchronized String getKeysDirectory() {
        return properties.getProperty(KEY_KEY_DIR);
    }

    public synchronized void setKeysDirectory(String dirPath) {
        if (dirPath != null && !dirPath.trim().isEmpty()) {
            properties.setProperty(KEY_KEY_DIR, dirPath.trim());
            saveToDisk();
        }
    }

    public synchronized Set<String> getEnabledPatterns() {
        String raw = properties.getProperty(KEY_PATTERNS, "");
        if (raw.trim().isEmpty()) {
            return new HashSet<>();
        }
        String[] tokens = raw.split(",");
        Set<String> set = new LinkedHashSet<>();
        for (String t : tokens) {
            if (!t.trim().isEmpty()) {
                set.add(t.trim());
            }
        }
        return set;
    }

    public synchronized void setEnabledPatterns(Set<String> patterns) {
        if (patterns == null) patterns = Collections.emptySet();
        properties.setProperty(KEY_PATTERNS, String.join(",", patterns));
        saveToDisk();
    }

    public synchronized boolean isPatternEnabled(String patternType) {
        return getEnabledPatterns().contains(patternType);
    }

    public synchronized void setPatternEnabled(String patternType, boolean enabled) {
        Set<String> current = getEnabledPatterns();
        if (enabled) {
            current.add(patternType);
        } else {
            current.remove(patternType);
        }
        setEnabledPatterns(current);
    }
}
