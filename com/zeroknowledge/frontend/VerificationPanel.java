package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.model.KeyInfo;
import com.zeroknowledge.model.OperationRecord;
import com.zeroknowledge.model.VerificationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.security.PublicKey;
import java.util.List;
import java.util.function.Consumer;

/**
 * Verification Workspace:
 * Verifies document authenticity and integrity using detached RSA digital signatures
 * and X.509 public keys.
 */
public class VerificationPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    // Files and Keys
    private File documentFile;
    private File signatureFile;
    private PublicKey activePublicKey;
    private String activeKeyAlias;

    // UI Fields
    private JTextField docPathField;
    private JTextField sigPathField;
    private JComboBox<String> keySourceComboBox;
    private JTextField customKeyPathField;
    private JButton browseCustomKeyBtn;
    private JButton verifyBtn;
    private JProgressBar progressBar;

    // Result Card
    private JPanel resultCard;
    private JLabel statusBadgeLabel;
    private JLabel statusHeaderLabel;
    private JLabel explanationLabel;
    private JLabel docHashLabel;
    private JLabel keyFingerprintLabel;
    private JLabel durationLabel;

    public VerificationPanel(BackendContext context, Consumer<String> navigationConsumer) {
        this.context = context;
        this.navigationConsumer = navigationConsumer;

        setLayout(new BorderLayout(0, 16));
        setBackground(ThemeManager.WORKSPACE_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        JPanel contentContainer = new JPanel();
        contentContainer.setLayout(new BoxLayout(contentContainer, BoxLayout.Y_AXIS));
        contentContainer.setOpaque(false);

        // Header
        contentContainer.add(createHeaderPanel());
        contentContainer.add(Box.createVerticalStrut(16));

        // Input Card
        contentContainer.add(createInputCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Result Card
        resultCard = createResultCard();
        resultCard.setVisible(false);
        contentContainer.add(resultCard);

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

        JLabel title = new JLabel("Document Verification Workspace");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel(
                "Cryptographically verify document integrity and detached digital signatures against known public keys."
        );
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

    private JPanel createInputCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JLabel cardTitle = new JLabel("Verification Inputs");
        cardTitle.setFont(ThemeManager.FONT_HEADER);
        cardTitle.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(cardTitle, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 4, 6, 4);

        // 1. Document file
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel docLbl = new JLabel("Document File:");
        docLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(docLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        docPathField = new JTextField();
        docPathField.setFont(ThemeManager.FONT_REGULAR);
        form.add(docPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JButton browseDocBtn = ThemeManager.createSecondaryButton("Browse Document...");
        browseDocBtn.addActionListener(e -> handleBrowseDocument());
        form.add(browseDocBtn, gbc);

        // 2. Detached signature file
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        JLabel sigLbl = new JLabel("Detached Signature (.sig):");
        sigLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(sigLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        sigPathField = new JTextField();
        sigPathField.setFont(ThemeManager.FONT_REGULAR);
        form.add(sigPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.0;
        JButton browseSigBtn = ThemeManager.createSecondaryButton("Browse Signature...");
        browseSigBtn.addActionListener(e -> handleBrowseSignature());
        form.add(browseSigBtn, gbc);

        // 3. Public Key selection
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0;
        JLabel keyLbl = new JLabel("Public Key Source:");
        keyLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(keyLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        keySourceComboBox = new JComboBox<>();
        keySourceComboBox.setFont(ThemeManager.FONT_SMALL);
        refreshKeySources();
        keySourceComboBox.addActionListener(e -> handleKeySourceChange());
        form.add(keySourceComboBox, gbc);

        gbc.gridx = 2; gbc.gridy = 2; gbc.weightx = 0.0;
        JButton refreshKeysBtn = ThemeManager.createSecondaryButton("Refresh Keys");
        refreshKeysBtn.addActionListener(e -> refreshKeySources());
        form.add(refreshKeysBtn, gbc);

        // 4. Custom Public Key file (PEM)
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0;
        JLabel customKeyLbl = new JLabel("Custom Key File (.pem):");
        customKeyLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(customKeyLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0;
        customKeyPathField = new JTextField();
        customKeyPathField.setFont(ThemeManager.FONT_REGULAR);
        customKeyPathField.setEnabled(false);
        form.add(customKeyPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 3; gbc.weightx = 0.0;
        browseCustomKeyBtn = ThemeManager.createSecondaryButton("Browse Key PEM...");
        browseCustomKeyBtn.setEnabled(false);
        browseCustomKeyBtn.addActionListener(e -> handleBrowseCustomKey());
        form.add(browseCustomKeyBtn, gbc);

        card.add(form, BorderLayout.CENTER);

        // Bottom verify button and progress
        JPanel bottomRow = new JPanel(new BorderLayout(10, 0));
        bottomRow.setOpaque(false);

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);
        bottomRow.add(progressBar, BorderLayout.CENTER);

        verifyBtn = ThemeManager.createPrimaryButton("Verify Signature & Integrity");
        verifyBtn.addActionListener(e -> handlePerformVerification());
        bottomRow.add(verifyBtn, BorderLayout.EAST);

        card.add(bottomRow, BorderLayout.SOUTH);
        return card;
    }

    private JPanel createResultCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);

        JLabel cardTitle = new JLabel("Cryptographic Verification Outcome");
        cardTitle.setFont(ThemeManager.FONT_HEADER);
        cardTitle.setForeground(ThemeManager.TEXT_PRIMARY);

        statusBadgeLabel = ThemeManager.createBadge("Pending", ThemeManager.CARD_BORDER, ThemeManager.TEXT_MUTED);

        top.add(cardTitle, BorderLayout.WEST);
        top.add(statusBadgeLabel, BorderLayout.EAST);
        card.add(top, BorderLayout.NORTH);

        JPanel details = new JPanel();
        details.setLayout(new BoxLayout(details, BoxLayout.Y_AXIS));
        details.setOpaque(false);

        statusHeaderLabel = new JLabel("Outcome: -");
        statusHeaderLabel.setFont(new Font("SansSerif", Font.BOLD, 15));
        details.add(statusHeaderLabel);
        details.add(Box.createVerticalStrut(8));

        explanationLabel = new JLabel("<html>Details will appear here.</html>");
        explanationLabel.setFont(ThemeManager.FONT_REGULAR);
        details.add(explanationLabel);
        details.add(Box.createVerticalStrut(12));

        docHashLabel = new JLabel("Computed Document Digest: -");
        docHashLabel.setFont(ThemeManager.FONT_MONO);
        docHashLabel.setForeground(ThemeManager.TEXT_SECONDARY);
        details.add(docHashLabel);
        details.add(Box.createVerticalStrut(4));

        keyFingerprintLabel = new JLabel("Public Key SHA-256 Fingerprint: -");
        keyFingerprintLabel.setFont(ThemeManager.FONT_MONO);
        keyFingerprintLabel.setForeground(ThemeManager.TEXT_SECONDARY);
        details.add(keyFingerprintLabel);
        details.add(Box.createVerticalStrut(4));

        durationLabel = new JLabel("Verification Time: -");
        durationLabel.setFont(ThemeManager.FONT_SMALL);
        durationLabel.setForeground(ThemeManager.TEXT_MUTED);
        details.add(durationLabel);

        card.add(details, BorderLayout.CENTER);
        return card;
    }

    private void handleBrowseDocument() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Document to Verify");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            documentFile = chooser.getSelectedFile();
            docPathField.setText(documentFile.getAbsolutePath());

            // Automatically check if adjacent .sig file exists
            File candidateSig = new File(documentFile.getAbsolutePath() + ".sig");
            if (candidateSig.exists()) {
                signatureFile = candidateSig;
                sigPathField.setText(candidateSig.getAbsolutePath());
            }
        }
    }

    private void handleBrowseSignature() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Detached Signature File (.sig)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            signatureFile = chooser.getSelectedFile();
            sigPathField.setText(signatureFile.getAbsolutePath());
        }
    }

    private void handleBrowseCustomKey() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Public Key File (.pem or .pub)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File keyFile = chooser.getSelectedFile();
            customKeyPathField.setText(keyFile.getAbsolutePath());
            try {
                activePublicKey = context.getCryptoService().loadPublicKeyFromPemFile(keyFile);
                activeKeyAlias = keyFile.getName();
            } catch (Exception ex) {
                DialogManager.showError(this, "Key Load Error", "Failed to parse public key PEM: " + ex.getMessage());
            }
        }
    }

    public void refreshKeySources() {
        keySourceComboBox.removeAllItems();
        List<KeyInfo> keys = context.getCryptoService().getAvailableKeyInfos();
        for (KeyInfo k : keys) {
            keySourceComboBox.addItem("Key: " + k.getAlias() + " (" + k.getKeySizeBits() + "-bit)");
        }
        keySourceComboBox.addItem("Custom PEM File...");
        if (keySourceComboBox.getItemCount() > 0) {
            keySourceComboBox.setSelectedIndex(0);
        }
    }

    private void handleKeySourceChange() {
        String selected = (String) keySourceComboBox.getSelectedItem();
        if (selected == null) return;

        boolean isCustom = selected.equals("Custom PEM File...");
        customKeyPathField.setEnabled(isCustom);
        browseCustomKeyBtn.setEnabled(isCustom);

        if (!isCustom) {
            // Find key in active crypto service
            List<KeyInfo> keys = context.getCryptoService().getAvailableKeyInfos();
            for (KeyInfo k : keys) {
                if (selected.contains("Key: " + k.getAlias())) {
                    activeKeyAlias = k.getAlias();
                    if (context.getCryptoService().getKeyPair(k.getAlias()) != null) {
                        activePublicKey = context.getCryptoService().getKeyPair(k.getAlias()).getPublic();
                    }
                    break;
                }
            }
        }
    }

    private void handlePerformVerification() {
        String docPath = docPathField.getText().trim();
        String sigPath = sigPathField.getText().trim();

        if (docPath.isEmpty()) {
            DialogManager.showError(this, "Missing Input", "Please select a document file to verify.");
            return;
        }
        if (sigPath.isEmpty()) {
            DialogManager.showError(this, "Missing Input", "Please select a detached signature file (.sig).");
            return;
        }

        File docFile = new File(docPath);
        File sigFile = new File(sigPath);

        if (!docFile.exists()) {
            DialogManager.showError(this, "File Not Found", "The specified document does not exist: " + docPath);
            return;
        }
        if (!sigFile.exists()) {
            DialogManager.showError(this, "File Not Found", "The specified signature file does not exist: " + sigPath);
            return;
        }

        // Determine public key
        String keySelection = (String) keySourceComboBox.getSelectedItem();
        if (keySelection != null && keySelection.equals("Custom PEM File...")) {
            String customPath = customKeyPathField.getText().trim();
            if (customPath.isEmpty()) {
                DialogManager.showError(this, "Missing Public Key", "Please select a custom PEM public key file.");
                return;
            }
            try {
                activePublicKey = context.getCryptoService().loadPublicKeyFromPemFile(new File(customPath));
            } catch (Exception ex) {
                DialogManager.showError(this, "Invalid Key", "Failed to load public key: " + ex.getMessage());
                return;
            }
        } else if (activePublicKey == null) {
            handleKeySourceChange();
        }

        progressBar.setVisible(true);
        verifyBtn.setEnabled(false);

        SwingWorker<VerificationResult, Void> worker = new SwingWorker<>() {
            @Override
            protected VerificationResult doInBackground() {
                return context.getCryptoService().verifySignature(docFile, sigFile, activePublicKey);
            }

            @Override
            protected void done() {
                progressBar.setVisible(false);
                verifyBtn.setEnabled(true);

                try {
                    VerificationResult result = get();
                    displayVerificationOutcome(result);

                    OperationRecord.Status opStatus = result.isValid() ?
                            OperationRecord.Status.SUCCESS : OperationRecord.Status.FAILED;

                    context.getAuditService().logOperation(
                            OperationRecord.OperationType.VERIFY,
                            docFile.getName(),
                            opStatus,
                            result.getStatus().getDisplayName() + ": " + result.getDetailedMessage()
                    );
                } catch (Exception ex) {
                    DialogManager.showError(VerificationPanel.this, "Verification Error",
                            "An unexpected error occurred during verification: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    private void displayVerificationOutcome(VerificationResult res) {
        resultCard.setVisible(true);

        VerificationResult.Status st = res.getStatus();
        statusHeaderLabel.setText("Result: " + st.getDisplayName());
        explanationLabel.setText("<html><body style='width: 500px;'>" + res.getDetailedMessage() + "</body></html>");
        docHashLabel.setText("Computed SHA-256: " + res.getComputedSha256());
        keyFingerprintLabel.setText("Public Key Fingerprint: " + res.getKeyFingerprint());
        durationLabel.setText("Execution time: " + res.getVerificationDurationMs() + " ms");

        switch (st) {
            case SIGNATURE_VALID:
                statusBadgeLabel.setText("SIGNATURE VALID");
                statusBadgeLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                statusHeaderLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                break;
            case DOCUMENT_MODIFIED_OR_MISMATCH:
                statusBadgeLabel.setText("MODIFIED OR MISMATCH");
                statusBadgeLabel.setForeground(ThemeManager.DANGER_RED);
                statusHeaderLabel.setForeground(ThemeManager.DANGER_RED);
                break;
            case SIGNATURE_MISSING_OR_INVALID:
                statusBadgeLabel.setText("INVALID SIGNATURE");
                statusBadgeLabel.setForeground(ThemeManager.DANGER_RED);
                statusHeaderLabel.setForeground(ThemeManager.DANGER_RED);
                break;
            case TRUSTED_PUBLIC_KEY_UNAVAILABLE:
                statusBadgeLabel.setText("NO PUBLIC KEY");
                statusBadgeLabel.setForeground(ThemeManager.WARNING_AMBER);
                statusHeaderLabel.setForeground(ThemeManager.WARNING_AMBER);
                break;
            case UNSUPPORTED_OPERATION:
                statusBadgeLabel.setText("UNSUPPORTED");
                statusBadgeLabel.setForeground(ThemeManager.WARNING_AMBER);
                statusHeaderLabel.setForeground(ThemeManager.WARNING_AMBER);
                break;
            case VERIFICATION_ERROR:
            case VERIFICATION_FAILED:
            default:
                statusBadgeLabel.setText("FAILED");
                statusBadgeLabel.setForeground(ThemeManager.DANGER_RED);
                statusHeaderLabel.setForeground(ThemeManager.DANGER_RED);
                break;
        }
    }
}
