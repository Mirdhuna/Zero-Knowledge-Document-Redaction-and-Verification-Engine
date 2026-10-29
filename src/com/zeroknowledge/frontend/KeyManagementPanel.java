package com.zeroknowledge.frontend;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Key Management Workspace:
 * Handles RSA key pair generation, public key inspection, X.509 PEM export/import,
 * encrypted private-key backup, and signing key selection.
 */
public class KeyManagementPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JTable keyTable;
    private DefaultTableModel keyTableModel;
    private JComboBox<Integer> keySizeComboBox;
    private JTextField keyAliasField;
    private JButton generateKeyBtn;
    private JProgressBar keyGenProgressBar;

    private JTextArea publicKeyPreviewArea;
    private JLabel activeKeyAliasLabel;
    private JLabel activeKeyFingerprintLabel;
    private JLabel activeKeyIdLabel;
    private JButton exportPublicKeyBtn;
    private JButton backupEncryptedKeyBtn;
    private JButton setActiveKeyBtn;
    private JButton importPublicKeyBtn;

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public KeyManagementPanel(BackendContext context, Consumer<String> navigationConsumer) {
        this.context = context;
        this.navigationConsumer = navigationConsumer;

        setLayout(new BorderLayout(0, 16));
        setBackground(ThemeManager.WORKSPACE_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
        refreshKeyTable();
    }

    private void initUI() {
        JPanel contentContainer = new JPanel();
        contentContainer.setLayout(new BoxLayout(contentContainer, BoxLayout.Y_AXIS));
        contentContainer.setOpaque(false);

        // Header
        contentContainer.add(createHeaderPanel());
        contentContainer.add(Box.createVerticalStrut(16));

        // Advisory Banner
        contentContainer.add(ThemeManager.createBanner(
                "<strong>Cryptographic Key Protection Policy:</strong> Private keys are held in memory during the session or saved exclusively via authenticated AES-256-GCM encryption with PBKDF2 derivation. Plaintext private keys are never exposed in the interface or exported.",
                ThemeManager.WARNING_BG,
                ThemeManager.WARNING_BORDER,
                ThemeManager.WARNING_AMBER,
                "⚠"
        ));
        contentContainer.add(Box.createVerticalStrut(16));

        // Generator Card
        contentContainer.add(createGeneratorCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Key List & Inspector
        contentContainer.add(createKeyInspectorCard());

        JScrollPane scroll = new JScrollPane(contentContainer);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.getVerticalScrollBar().setUnitIncrement(16);

        add(scroll, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel title = new JLabel("Cryptographic Key Management");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel("Generate asymmetric RSA key pairs, export public keys for distribution, and manage signing identities.");
        desc.setFont(ThemeManager.FONT_REGULAR);
        desc.setForeground(ThemeManager.TEXT_SECONDARY);

        left.add(title);
        left.add(desc);

        JButton backBtn = ThemeManager.createSecondaryButton("← Dashboard");
        backBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_DASHBOARD));

        panel.add(left, BorderLayout.WEST);
        panel.add(backBtn, BorderLayout.EAST);
        return panel;
    }

    private JPanel createGeneratorCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Generate New RSA Key Pair");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 4, 6, 4);

        // Alias
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel aliasLbl = new JLabel("Key Alias:");
        aliasLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(aliasLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        keyAliasField = new JTextField("signing-key-" + (System.currentTimeMillis() % 1000));
        keyAliasField.setFont(ThemeManager.FONT_REGULAR);
        form.add(keyAliasField, gbc);

        // Key Size
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel sizeLbl = new JLabel("Key Size:");
        sizeLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(sizeLbl, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.0;
        keySizeComboBox = new JComboBox<>(new Integer[]{2048, 3072, 4096});
        keySizeComboBox.setSelectedItem(3072);
        keySizeComboBox.setFont(ThemeManager.FONT_SMALL);
        form.add(keySizeComboBox, gbc);

        // Generate Button
        gbc.gridx = 4; gbc.gridy = 0; gbc.weightx = 0.0;
        generateKeyBtn = ThemeManager.createPrimaryButton("Generate RSA Key");
        generateKeyBtn.addActionListener(e -> handleGenerateKey());
        form.add(generateKeyBtn, gbc);

        card.add(form, BorderLayout.CENTER);

        keyGenProgressBar = new JProgressBar();
        keyGenProgressBar.setIndeterminate(true);
        keyGenProgressBar.setVisible(false);
        card.add(keyGenProgressBar, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createKeyInspectorCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        JLabel title = new JLabel("Configured Cryptographic Keys");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        importPublicKeyBtn = ThemeManager.createSecondaryButton("Import Public Key (PEM)...");
        importPublicKeyBtn.addActionListener(e -> handleImportPublicKey());

        top.add(title, BorderLayout.WEST);
        top.add(importPublicKeyBtn, BorderLayout.EAST);
        card.add(top, BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.52);
        splitPane.setBorder(null);
        splitPane.setOpaque(false);

        // Left Table
        String[] columns = {"Active", "Alias", "Key Identifier", "Capabilities"};
        keyTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        keyTable = new JTable(keyTableModel);
        ThemeManager.styleTable(keyTable);
        keyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && keyTable.getSelectedRow() >= 0) {
                int row = keyTable.getSelectedRow();
                String alias = (String) keyTableModel.getValueAt(row, 1);
                displayKeyDetails(alias);
            }
        });

        JScrollPane tableScroll = new JScrollPane(keyTable);
        tableScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScroll.getViewport().setBackground(ThemeManager.CARD_BG);
        splitPane.setLeftComponent(tableScroll);

        // Right Detail Card
        JPanel rightPanel = new JPanel(new BorderLayout(0, 8));
        rightPanel.setOpaque(false);
        rightPanel.setBorder(new EmptyBorder(0, 10, 0, 0));

        JPanel detailsHeader = new JPanel();
        detailsHeader.setLayout(new BoxLayout(detailsHeader, BoxLayout.Y_AXIS));
        detailsHeader.setOpaque(false);

        activeKeyAliasLabel = new JLabel("Selected: None");
        activeKeyAliasLabel.setFont(ThemeManager.FONT_SUBHEADER);

        activeKeyIdLabel = new JLabel("Key ID: -");
        activeKeyIdLabel.setFont(ThemeManager.FONT_MONO);
        activeKeyIdLabel.setForeground(ThemeManager.PRIMARY_BLUE);

        activeKeyFingerprintLabel = new JLabel("Full SHA-256 Fingerprint: -");
        activeKeyFingerprintLabel.setFont(ThemeManager.FONT_MONO);
        activeKeyFingerprintLabel.setForeground(ThemeManager.TEXT_SECONDARY);

        detailsHeader.add(activeKeyAliasLabel);
        detailsHeader.add(Box.createVerticalStrut(4));
        detailsHeader.add(activeKeyIdLabel);
        detailsHeader.add(Box.createVerticalStrut(4));
        detailsHeader.add(activeKeyFingerprintLabel);
        rightPanel.add(detailsHeader, BorderLayout.NORTH);

        publicKeyPreviewArea = new JTextArea();
        publicKeyPreviewArea.setFont(ThemeManager.FONT_MONO);
        publicKeyPreviewArea.setEditable(false);
        publicKeyPreviewArea.setBackground(new Color(248, 250, 252));
        publicKeyPreviewArea.setBorder(new EmptyBorder(8, 8, 8, 8));

        JScrollPane pemScroll = new JScrollPane(publicKeyPreviewArea);
        pemScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        rightPanel.add(pemScroll, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnRow.setOpaque(false);

        setActiveKeyBtn = ThemeManager.createSecondaryButton("Set Active Signing Key");
        setActiveKeyBtn.setEnabled(false);
        setActiveKeyBtn.addActionListener(e -> handleSetActiveKey());

        backupEncryptedKeyBtn = ThemeManager.createSecondaryButton("Backup Encrypted Key (.zkkey)...");
        backupEncryptedKeyBtn.setEnabled(false);
        backupEncryptedKeyBtn.addActionListener(e -> handleBackupEncryptedKey());

        exportPublicKeyBtn = ThemeManager.createPrimaryButton("Export Public Key (PEM)...");
        exportPublicKeyBtn.setEnabled(false);
        exportPublicKeyBtn.addActionListener(e -> handleExportPublicKey());

        btnRow.add(setActiveKeyBtn);
        btnRow.add(backupEncryptedKeyBtn);
        btnRow.add(exportPublicKeyBtn);
        rightPanel.add(btnRow, BorderLayout.SOUTH);

        splitPane.setRightComponent(rightPanel);
        card.add(splitPane, BorderLayout.CENTER);

        return card;
    }

    private void handleGenerateKey() {
        String alias = keyAliasField.getText().trim();
        if (alias.isEmpty()) {
            DialogManager.showError(this, "Input Required", "Please enter an alias for the new key.");
            return;
        }

        int keySize = (Integer) keySizeComboBox.getSelectedItem();

        boolean confirm = DialogManager.showConfirmation(this, "Confirm Key Generation",
                "Generate a new " + keySize + "-bit RSA key pair with alias '" + alias + "'?\n" +
                        "This identity will be available for detached document signing.", "Generate Key");
        if (!confirm) return;

        generateKeyBtn.setEnabled(false);
        keyGenProgressBar.setVisible(true);

        SwingWorker<KeyPair, Void> worker = new SwingWorker<>() {
            @Override
            protected KeyPair doInBackground() throws Exception {
                return context.getKeyManager().generateKeyPair(keySize);
            }

            @Override
            protected void done() {
                generateKeyBtn.setEnabled(true);
                keyGenProgressBar.setVisible(false);

                try {
                    KeyPair kp = get();
                    context.registerKeyPair(alias, kp);
                    refreshKeyTable();
                    displayKeyDetails(alias);
                    DialogManager.showInfo(KeyManagementPanel.this, "Key Generated",
                            "RSA " + keySize + "-bit key pair '" + alias + "' generated successfully.");
                } catch (Exception ex) {
                    DialogManager.showError(KeyManagementPanel.this, "Generation Error",
                            "Failed to generate key pair: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    private void handleImportPublicKey() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Public Key File (.pem or .pub)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File keyFile = chooser.getSelectedFile();
            try {
                PublicKey pk = context.getKeyManager().loadPublicKey(keyFile.toPath());
                String alias = keyFile.getName().replace(".pem", "").replace(".pub", "");
                context.registerPublicKey(alias, pk);
                refreshKeyTable();
                DialogManager.showInfo(this, "Key Imported", "Public key imported successfully from:\n" + keyFile.getName());
            } catch (Exception ex) {
                DialogManager.showError(this, "Import Error", "Failed to parse public key: " + ex.getMessage());
            }
        }
    }

    private void handleExportPublicKey() {
        int row = keyTable.getSelectedRow();
        if (row < 0) return;
        String alias = (String) keyTableModel.getValueAt(row, 1);
        PublicKey pk = context.getKnownPublicKeys().get(alias);
        if (pk == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(alias + "_public_key.pem"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            try {
                context.getKeyManager().exportPublicKey(pk, dest.toPath());
                DialogManager.showInfo(this, "Export Succeeded",
                        "Public key exported in X.509 PEM format to:\n" + dest.getAbsolutePath());
            } catch (Exception ex) {
                DialogManager.showError(this, "Export Error", "Failed to export public key: " + ex.getMessage());
            }
        }
    }

    private void handleBackupEncryptedKey() {
        int row = keyTable.getSelectedRow();
        if (row < 0) return;
        String alias = (String) keyTableModel.getValueAt(row, 1);
        KeyPair kp = context.getSessionKeyPairs().get(alias);
        if (kp == null) {
            DialogManager.showWarning(this, "Unavailable", "Only keys with in-memory private keys can be encrypted and backed up.");
            return;
        }

        JPasswordField pwd = new JPasswordField(16);
        int opt = JOptionPane.showConfirmDialog(this, pwd, "Enter Passphrase for Encrypted Private-Key Backup (AES-256-GCM):",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (opt != JOptionPane.OK_OPTION || pwd.getPassword().length == 0) {
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(alias + ".zkkey"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            try {
                context.getKeyManager().saveEncryptedPrivateKey(
                        kp.getPrivate(),
                        kp.getPublic(),
                        pwd.getPassword(),
                        dest.toPath()
                );
                DialogManager.showInfo(this, "Backup Complete",
                        "Encrypted private key written to:\n" + dest.getAbsolutePath());
            } catch (Exception ex) {
                DialogManager.showError(this, "Backup Failed", "Failed to encrypt and save private key: " + ex.getMessage());
            }
        }
    }

    private void handleSetActiveKey() {
        int row = keyTable.getSelectedRow();
        if (row < 0) return;
        String alias = (String) keyTableModel.getValueAt(row, 1);
        if (context.getSessionKeyPairs().containsKey(alias)) {
            context.setActiveKeyAlias(alias);
            refreshKeyTable();
            displayKeyDetails(alias);
            DialogManager.showInfo(this, "Active Key Updated", "Active signing key updated to: " + alias);
        } else {
            DialogManager.showWarning(this, "Signing Unavailable",
                    "This identity only has a public key and cannot be used for signing.");
        }
    }

    private void displayKeyDetails(String alias) {
        PublicKey pk = context.getKnownPublicKeys().get(alias);
        if (pk == null) return;

        try {
            String keyId = context.getKeyManager().getKeyIdentifier(pk);
            String fingerprint = context.getKeyManager().getFullKeyFingerprint(pk);

            activeKeyAliasLabel.setText("Selected: " + alias);
            activeKeyIdLabel.setText("Key ID: " + keyId);
            activeKeyFingerprintLabel.setText("Full SHA-256 Fingerprint: " + fingerprint);

            // Generate PEM string
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            Path temp = Files.createTempFile("pem_preview", ".pem");
            context.getKeyManager().exportPublicKey(pk, temp);
            String pem = Files.readString(temp);
            Files.deleteIfExists(temp);
            publicKeyPreviewArea.setText(pem);

            exportPublicKeyBtn.setEnabled(true);
            boolean hasPriv = context.getSessionKeyPairs().containsKey(alias);
            setActiveKeyBtn.setEnabled(hasPriv);
            backupEncryptedKeyBtn.setEnabled(hasPriv);
        } catch (Exception e) {
            publicKeyPreviewArea.setText("Error reading key details: " + e.getMessage());
        }
    }

    public void refreshKeyTable() {
        keyTableModel.setRowCount(0);
        Map<String, PublicKey> keys = context.getKnownPublicKeys();
        String active = context.getActiveKeyAlias();

        for (String alias : keys.keySet()) {
            boolean isActive = alias.equals(active);
            boolean hasPrivate = context.getSessionKeyPairs().containsKey(alias);
            PublicKey pk = keys.get(alias);

            String keyId = "-";
            try {
                keyId = context.getKeyManager().getKeyIdentifier(pk);
            } catch (Exception ignored) {}

            keyTableModel.addRow(new Object[]{
                    isActive ? "★ Active" : "",
                    alias,
                    keyId,
                    hasPrivate ? "Signing + Verification" : "Verification Only"
            });
        }

        if (keyTable.getRowCount() > 0 && keyTable.getSelectedRow() < 0) {
            keyTable.setRowSelectionInterval(0, 0);
        }
    }
}
