package com.zeroknowledge.frontend;

import com.zeroknowledge.model.VerificationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Verification Workspace:
 * Verifies document authenticity and integrity using detached RSA digital signatures (.zksig)
 * and trusted X.509 public keys.
 */
public class VerificationPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private File documentFile;
    private File signatureFile;
    private PublicKey activePublicKey;

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
    private JLabel keyIdLabel;
    private JLabel technicalDetailsLabel;

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
        contentContainer.add(Box.createVerticalStrut(14));

        // Educational Workflow Banner
        contentContainer.add(ThemeManager.createBanner(
                "<strong>How Cryptographic Verification Works:</strong> The engine recalculates a live streaming SHA-256 digest over the target document's exact bytes, and mathematically evaluates the detached RSA signature (<code>.zksig</code>) against the trusted public key identity. If even a single byte or space is altered, the signature is rejected.",
                new Color(239, 246, 255),
                new Color(191, 219, 254),
                ThemeManager.PRIMARY_BLUE,
                "🛡️"
        ));
        contentContainer.add(Box.createVerticalStrut(14));

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
                "Cryptographically verify document integrity and detached digital signatures (.zksig) against trusted public keys."
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

        JPanel stepHeader = ThemeManager.createStepHeader(
                1,
                "Target Document, Detached Signature & Public Key",
                "Supply the three verification elements. Click an auto-fill button below to test with sample or recently redacted files."
        );
        card.add(stepHeader, BorderLayout.NORTH);

        JPanel centerContainer = new JPanel();
        centerContainer.setLayout(new BoxLayout(centerContainer, BoxLayout.Y_AXIS));
        centerContainer.setOpaque(false);

        // Quick auto-fill toolbar
        JPanel quickBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        quickBar.setOpaque(false);

        JLabel quickLbl = new JLabel("Quick Actions:");
        quickLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        quickLbl.setForeground(ThemeManager.TEXT_SECONDARY);
        quickBar.add(quickLbl);

        JButton autoFillRecentBtn = ThemeManager.createSecondaryButton("⚡ Auto-Fill Last Redacted Document");
        autoFillRecentBtn.setToolTipText("Load the document and .zksig signature generated in your most recent redaction");
        autoFillRecentBtn.addActionListener(e -> handleAutoFillRecent());

        JButton loadSamplePairBtn = ThemeManager.createSecondaryButton("📄 Load Sample Contract Pair (.pdf)");
        loadSamplePairBtn.setToolTipText("Load pre-configured sample contract PDF and detached signature");
        loadSamplePairBtn.addActionListener(e -> handleLoadSamplePair());

        quickBar.add(autoFillRecentBtn);
        quickBar.add(loadSamplePairBtn);

        centerContainer.add(quickBar);
        centerContainer.add(Box.createVerticalStrut(10));

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 6, 8, 6);

        // 1. Document file
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel docLbl = new JLabel("Target Document File:");
        docLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(docLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        docPathField = ThemeManager.createTextField();
        form.add(docPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JButton browseDocBtn = ThemeManager.createSecondaryButton("Browse Document...");
        browseDocBtn.addActionListener(e -> handleBrowseDocument());
        form.add(browseDocBtn, gbc);

        // 2. Detached signature file
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        JLabel sigLbl = new JLabel("Detached Signature (.zksig):");
        sigLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(sigLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        sigPathField = ThemeManager.createTextField();
        form.add(sigPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.0;
        JButton browseSigBtn = ThemeManager.createSecondaryButton("Browse Signature...");
        browseSigBtn.addActionListener(e -> handleBrowseSignature());
        form.add(browseSigBtn, gbc);

        // 3. Public Key selection
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0;
        JLabel keyLbl = new JLabel("Trusted Verification Public Key:");
        keyLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(keyLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        keySourceComboBox = ThemeManager.createComboBox();
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
        customKeyPathField = ThemeManager.createTextField();
        customKeyPathField.setEnabled(false);
        form.add(customKeyPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 3; gbc.weightx = 0.0;
        browseCustomKeyBtn = ThemeManager.createSecondaryButton("Browse PEM...");
        browseCustomKeyBtn.setEnabled(false);
        browseCustomKeyBtn.addActionListener(e -> handleBrowseCustomKey());
        form.add(browseCustomKeyBtn, gbc);

        centerContainer.add(form);
        card.add(centerContainer, BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new BorderLayout(10, 0));
        bottomRow.setOpaque(false);

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);
        bottomRow.add(progressBar, BorderLayout.CENTER);

        verifyBtn = ThemeManager.createPrimaryButton("Verify Signature & Document Integrity →");
        verifyBtn.addActionListener(e -> handlePerformVerification());
        bottomRow.add(verifyBtn, BorderLayout.EAST);

        card.add(bottomRow, BorderLayout.SOUTH);
        return card;
    }

    private void handleAutoFillRecent() {
        Path lastDoc = context.getLastRedactedDocumentPath();
        Path lastSig = context.getLastSignaturePath();
        if (lastDoc != null && Files.exists(lastDoc)) {
            loadFilesForVerification(lastDoc, lastSig);
        } else {
            DialogManager.showInfo(this, "No Recent Redaction",
                    "No redacted document found in the current session.\nPlease redact a document first or load a sample pair.");
        }
    }

    private void handleLoadSamplePair() {
        Path sampleDoc = Path.of("samples/sample_contract.pdf");
        Path sampleSig = Path.of("samples/sample_contract.pdf.zksig");
        if (!Files.exists(sampleDoc)) {
            sampleDoc = Path.of("../samples/sample_contract.pdf");
            sampleSig = Path.of("../samples/sample_contract.pdf.zksig");
        }
        if (Files.exists(sampleDoc)) {
            if (!Files.exists(sampleSig)) {
                try {
                    KeyPair kp = context.getActiveKeyPair();
                    if (kp != null) {
                        context.getSignatureService().signAndSaveDetached(sampleDoc, kp.getPrivate(), kp.getPublic(), sampleSig);
                    }
                } catch (Exception ignored) {
                }
            }
            if (Files.exists(sampleSig)) {
                loadFilesForVerification(sampleDoc, sampleSig);
                return;
            }
        }
        DialogManager.showError(this, "Sample Error", "Sample verification pair could not be prepared from samples/ directory.");
    }

    public void loadFilesForVerification(Path documentPath, Path signaturePath) {
        if (documentPath != null) {
            this.documentFile = documentPath.toFile();
            docPathField.setText(documentPath.toAbsolutePath().toString());
        }
        if (signaturePath != null) {
            this.signatureFile = signaturePath.toFile();
            sigPathField.setText(signaturePath.toAbsolutePath().toString());
        } else if (documentPath != null) {
            Path candidate = context.getDocumentService().getFileStorageService().resolveDefaultSignaturePath(documentPath);
            if (Files.exists(candidate)) {
                this.signatureFile = candidate.toFile();
                sigPathField.setText(candidate.toAbsolutePath().toString());
            }
        }
        refreshKeySources();
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

        statusHeaderLabel = new JLabel("Status: -");
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

        keyIdLabel = new JLabel("Public Key ID: -");
        keyIdLabel.setFont(ThemeManager.FONT_MONO);
        keyIdLabel.setForeground(ThemeManager.TEXT_SECONDARY);
        details.add(keyIdLabel);
        details.add(Box.createVerticalStrut(4));

        technicalDetailsLabel = new JLabel("Technical Notes: -");
        technicalDetailsLabel.setFont(ThemeManager.FONT_SMALL);
        technicalDetailsLabel.setForeground(ThemeManager.TEXT_MUTED);
        details.add(technicalDetailsLabel);

        card.add(details, BorderLayout.CENTER);
        return card;
    }

    private void handleBrowseDocument() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Target Document to Verify");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            documentFile = chooser.getSelectedFile();
            docPathField.setText(documentFile.getAbsolutePath());

            // Automatically check for standard .zksig or .sig adjacent file
            Path defaultZkSig = context.getDocumentService().getFileStorageService()
                    .resolveDefaultSignaturePath(documentFile.toPath());
            if (defaultZkSig.toFile().exists()) {
                signatureFile = defaultZkSig.toFile();
                sigPathField.setText(signatureFile.getAbsolutePath());
            } else {
                File candidateSig = new File(documentFile.getAbsolutePath() + ".sig");
                if (candidateSig.exists()) {
                    signatureFile = candidateSig;
                    sigPathField.setText(candidateSig.getAbsolutePath());
                }
            }
        }
    }

    private void handleBrowseSignature() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Detached Signature File (.zksig)");
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
                activePublicKey = context.getKeyManager().loadPublicKey(keyFile.toPath());
            } catch (Exception ex) {
                DialogManager.showError(this, "Key Load Error", "Failed to parse public key: " + ex.getMessage());
            }
        }
    }

    public void refreshKeySources() {
        keySourceComboBox.removeAllItems();
        Map<String, PublicKey> keys = context.getKnownPublicKeys();
        for (String alias : keys.keySet()) {
            keySourceComboBox.addItem("Key: " + alias);
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
            String alias = selected.replace("Key: ", "").trim();
            activePublicKey = context.getKnownPublicKeys().get(alias);
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
            DialogManager.showError(this, "Missing Input", "Please select a detached signature file (.zksig).");
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

        String keySelection = (String) keySourceComboBox.getSelectedItem();
        if (keySelection != null && keySelection.equals("Custom PEM File...")) {
            String customPath = customKeyPathField.getText().trim();
            if (customPath.isEmpty()) {
                DialogManager.showError(this, "Missing Public Key", "Please select a custom PEM public key file.");
                return;
            }
            try {
                activePublicKey = context.getKeyManager().loadPublicKey(new File(customPath).toPath());
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
                return context.getVerificationService().verifyDocument(
                        docFile.toPath(),
                        sigFile.toPath(),
                        activePublicKey
                );
            }

            @Override
            protected void done() {
                progressBar.setVisible(false);
                verifyBtn.setEnabled(true);

                try {
                    VerificationResult result = get();
                    displayVerificationOutcome(result);
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
        statusHeaderLabel.setText("Outcome: " + st.name());
        explanationLabel.setText("<html><body style='width: 500px;'>" + res.getUserSafeExplanation() + "</body></html>");
        docHashLabel.setText("Computed SHA-256: " + (res.getCalculatedDocumentDigest().isEmpty() ? "N/A" : res.getCalculatedDocumentDigest()));
        keyIdLabel.setText("Key Identifier: " + (res.getPublicKeyId().isEmpty() ? "N/A" : res.getPublicKeyId()));
        technicalDetailsLabel.setText("Details: " + (res.getTechnicalDetails().isEmpty() ? "None" : res.getTechnicalDetails()));

        switch (st) {
            case VALID_SIGNATURE:
                statusBadgeLabel.setText("SIGNATURE VALID");
                statusBadgeLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                statusHeaderLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                break;
            case SIGNATURE_MISMATCH_OR_MODIFIED:
                statusBadgeLabel.setText("MODIFIED / MISMATCH");
                statusBadgeLabel.setForeground(ThemeManager.DANGER_RED);
                statusHeaderLabel.setForeground(ThemeManager.DANGER_RED);
                break;
            case MISSING_SIGNATURE_OR_METADATA:
            case INVALID_SIGNATURE_ENCODING:
                statusBadgeLabel.setText("INVALID SIGNATURE");
                statusBadgeLabel.setForeground(ThemeManager.WARNING_AMBER);
                statusHeaderLabel.setForeground(ThemeManager.WARNING_AMBER);
                break;
            case MISSING_OR_UNTRUSTED_PUBLIC_KEY:
                statusBadgeLabel.setText("UNTRUSTED KEY");
                statusBadgeLabel.setForeground(ThemeManager.WARNING_AMBER);
                statusHeaderLabel.setForeground(ThemeManager.WARNING_AMBER);
                break;
            case UNSUPPORTED_OPERATION:
                statusBadgeLabel.setText("UNSUPPORTED");
                statusBadgeLabel.setForeground(ThemeManager.WARNING_AMBER);
                statusHeaderLabel.setForeground(ThemeManager.WARNING_AMBER);
                break;
            case PROCESSING_FAILURE:
            default:
                statusBadgeLabel.setText("FAILED");
                statusBadgeLabel.setForeground(ThemeManager.DANGER_RED);
                statusHeaderLabel.setForeground(ThemeManager.DANGER_RED);
                break;
        }
    }
}
