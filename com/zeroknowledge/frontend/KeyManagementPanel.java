package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.model.KeyInfo;
import com.zeroknowledge.model.OperationRecord;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.function.Consumer;

/**
 * Key Management Workspace:
 * Handles RSA key pair generation, public key inspection, PEM export/import,
 * and key selection for signing operations.
 */
public class KeyManagementPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    // UI Components
    private JTable keyTable;
    private DefaultTableModel keyTableModel;
    private JComboBox<Integer> keySizeComboBox;
    private JTextField keyAliasField;
    private JButton generateKeyBtn;
    private JProgressBar keyGenProgressBar;

    private JTextArea publicKeyPreviewArea;
    private JLabel activeKeyAliasLabel;
    private JLabel activeKeyFingerprintLabel;
    private JButton exportPublicKeyBtn;
    private JButton setActiveKeyBtn;
    private JButton importPublicKeyBtn;

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

        // Key Storage Security Warning Banner
        contentContainer.add(ThemeManager.createBanner(
                "<strong>Cryptographic Key Storage Advisory:</strong> Keys created in this session are held in-memory for signing and verification. Private key contents are never exposed in the interface or exported in plaintext. Store exported public keys securely.",
                ThemeManager.WARNING_BG,
                ThemeManager.WARNING_BORDER,
                ThemeManager.WARNING_AMBER,
                "⚠"
        ));
        contentContainer.add(Box.createVerticalStrut(16));

        // Generator Card
        contentContainer.add(createGeneratorCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Keys List & Inspector Card
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
        JLabel sizeLbl = new JLabel("Key Length:");
        sizeLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(sizeLbl, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.0;
        keySizeComboBox = new JComboBox<>(new Integer[]{2048, 3072, 4096});
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

        // Split pane: Left = Key Table, Right = Details & Public Key PEM
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.55);
        splitPane.setBorder(null);
        splitPane.setOpaque(false);

        // Left Table
        String[] columns = {"Active", "Alias", "Algorithm", "Size", "Created", "Private Key"};
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

        activeKeyFingerprintLabel = new JLabel("SHA-256 Fingerprint: -");
        activeKeyFingerprintLabel.setFont(ThemeManager.FONT_MONO);
        activeKeyFingerprintLabel.setForeground(ThemeManager.TEXT_SECONDARY);

        detailsHeader.add(activeKeyAliasLabel);
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

        setActiveKeyBtn = ThemeManager.createSecondaryButton("Set as Active Signing Key");
        setActiveKeyBtn.setEnabled(false);
        setActiveKeyBtn.addActionListener(e -> handleSetActiveKey());

        exportPublicKeyBtn = ThemeManager.createPrimaryButton("Export Public Key (PEM)...");
        exportPublicKeyBtn.setEnabled(false);
        exportPublicKeyBtn.addActionListener(e -> handleExportPublicKey());

        btnRow.add(setActiveKeyBtn);
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
                        "This will initialize a new in-memory cryptographic signing key.", "Generate");
        if (!confirm) return;

        generateKeyBtn.setEnabled(false);
        keyGenProgressBar.setVisible(true);

        SwingWorker<KeyInfo, Void> worker = new SwingWorker<>() {
            @Override
            protected KeyInfo doInBackground() throws Exception {
                return context.getCryptoService().generateKeyPair(keySize, alias);
            }

            @Override
            protected void done() {
                generateKeyBtn.setEnabled(true);
                keyGenProgressBar.setVisible(false);

                try {
                    KeyInfo info = get();
                    refreshKeyTable();
                    displayKeyDetails(info.getAlias());

                    context.getAuditService().logOperation(
                            OperationRecord.OperationType.KEY_GENERATION,
                            alias,
                            OperationRecord.Status.SUCCESS,
                            "Generated RSA " + keySize + "-bit key. Fingerprint: " +
                                    (info.getFingerprintSha256().length() > 16 ?
                                            info.getFingerprintSha256().substring(0, 16) + "..." : info.getFingerprintSha256())
                    );

                    DialogManager.showInfo(KeyManagementPanel.this, "Key Generated",
                            "RSA " + keySize + "-bit key pair '" + alias + "' created successfully.");
                } catch (Exception ex) {
                    DialogManager.showError(KeyManagementPanel.this, "Generation Failed",
                            "Failed to generate RSA key: " + ex.getMessage());
                    context.getAuditService().logOperation(
                            OperationRecord.OperationType.KEY_GENERATION,
                            alias,
                            OperationRecord.Status.FAILED,
                            "Error: " + ex.getMessage()
                    );
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
                context.getCryptoService().loadPublicKeyFromPemFile(keyFile);
                refreshKeyTable();
                context.getAuditService().logOperation(
                        OperationRecord.OperationType.KEY_IMPORT,
                        keyFile.getName(),
                        OperationRecord.Status.SUCCESS,
                        "Imported public key from " + keyFile.getAbsolutePath()
                );
                DialogManager.showInfo(this, "Key Imported", "Public key imported successfully from:\n" + keyFile.getName());
            } catch (Exception ex) {
                DialogManager.showError(this, "Import Error", "Failed to import public key: " + ex.getMessage());
            }
        }
    }

    private void handleExportPublicKey() {
        int row = keyTable.getSelectedRow();
        if (row < 0) return;
        String alias = (String) keyTableModel.getValueAt(row, 1);
        KeyInfo info = context.getCryptoService().getKeyInfo(alias);
        if (info == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(alias + "_public_key.pem"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            try {
                var kp = context.getCryptoService().getKeyPair(alias);
                if (kp != null) {
                    context.getCryptoService().exportPublicKeyToPemFile(kp.getPublic(), dest);
                } else {
                    java.nio.file.Files.writeString(dest.toPath(), info.getPublicKeyPem());
                }

                context.getAuditService().logOperation(
                        OperationRecord.OperationType.KEY_EXPORT,
                        alias,
                        OperationRecord.Status.SUCCESS,
                        "Exported public key to " + dest.getAbsolutePath()
                );

                DialogManager.showInfo(this, "Export Succeeded",
                        "Public key exported in X.509 PEM format to:\n" + dest.getAbsolutePath());
            } catch (Exception ex) {
                DialogManager.showError(this, "Export Error", "Failed to export public key: " + ex.getMessage());
            }
        }
    }

    private void handleSetActiveKey() {
        int row = keyTable.getSelectedRow();
        if (row < 0) return;
        String alias = (String) keyTableModel.getValueAt(row, 1);
        KeyInfo info = context.getCryptoService().getKeyInfo(alias);
        if (info != null && info.isPrivateKeyAvailable()) {
            context.getCryptoService().setSelectedAlias(alias);
            refreshKeyTable();
            displayKeyDetails(alias);
            DialogManager.showInfo(this, "Active Key Set", "Active signing key updated to: " + alias);
        } else {
            DialogManager.showWarning(this, "Unavailable Key",
                    "This key only contains a public key and cannot be used for signing documents.");
        }
    }

    private void displayKeyDetails(String alias) {
        KeyInfo info = context.getCryptoService().getKeyInfo(alias);
        if (info == null) return;

        activeKeyAliasLabel.setText("Selected Key: " + info.getAlias() + " (" + info.getKeySizeBits() + "-bit " + info.getAlgorithm() + ")");
        activeKeyFingerprintLabel.setText("SHA-256 Fingerprint: " + info.getFingerprintSha256());
        publicKeyPreviewArea.setText(info.getPublicKeyPem());

        exportPublicKeyBtn.setEnabled(true);
        setActiveKeyBtn.setEnabled(info.isPrivateKeyAvailable());
    }

    public void refreshKeyTable() {
        keyTableModel.setRowCount(0);
        List<KeyInfo> keys = context.getCryptoService().getAvailableKeyInfos();
        String active = context.getCryptoService().getSelectedAlias();

        for (KeyInfo k : keys) {
            boolean isActive = k.getAlias().equals(active);
            keyTableModel.addRow(new Object[]{
                    isActive ? "★ Active" : "",
                    k.getAlias(),
                    k.getAlgorithm(),
                    k.getKeySizeBits() + "-bit",
                    k.getFormattedCreatedAt(),
                    k.isPrivateKeyAvailable() ? "In-Memory (Signing Ready)" : "Public Key Only"
            });
        }

        if (keyTable.getRowCount() > 0 && keyTable.getSelectedRow() < 0) {
            keyTable.setRowSelectionInterval(0, 0);
        }
    }
}
