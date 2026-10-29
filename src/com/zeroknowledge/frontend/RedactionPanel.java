package com.zeroknowledge.frontend;

import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 5-Step Redaction Workspace:
 * 1. Document Selection & Capability Verification
 * 2. Background Sensitive Data Scanning
 * 3. Review & Selection of Candidates
 * 4. Destination & Detached Signing Configuration
 * 5. Redaction Execution & Cryptographic Verification Summary
 */
public class RedactionPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    // State
    private File selectedFile;
    private DocumentMetadata documentMetadata;
    private List<RedactionMatch> currentMatches = new ArrayList<>();

    // UI Components - Step 1: File selection
    private JLabel fileNameLabel;
    private JLabel fileSizeLabel;
    private JLabel fileTypeLabel;
    private JLabel fileShaLabel;
    private JLabel capabilityStatusBadge;
    private JButton chooseFileBtn;
    private JButton scanBtn;

    // UI Components - Step 2 & 3: Candidates Table
    private JTable candidateTable;
    private DefaultTableModel candidateTableModel;
    private JButton selectAllBtn;
    private JButton deselectAllBtn;
    private JLabel candidateCountLabel;
    private JProgressBar scanProgressBar;

    // UI Components - Step 4: Output & Signing
    private JTextField outputPathField;
    private JButton browseOutputBtn;
    private JCheckBox signOutputCheckBox;
    private JComboBox<String> keySelectorComboBox;
    private JButton applyRedactionBtn;

    // UI Components - Step 5: Result Card
    private JPanel resultCard;
    private JLabel resultStatusLabel;
    private JLabel resultOutputLocationLabel;
    private JLabel resultCountLabel;
    private JLabel resultHashesLabel;
    private JLabel resultSignatureLabel;

    public RedactionPanel(BackendContext context, Consumer<String> navigationConsumer) {
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

        // Step 1: File Selection & Capability Check
        contentContainer.add(createFileSelectionCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Steps 2 & 3: Scan & Candidates Review
        contentContainer.add(createCandidatesCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 4: Output & Detached Signing
        contentContainer.add(createExecutionCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 5: Result Summary
        resultCard = createResultCard();
        resultCard.setVisible(false);
        contentContainer.add(resultCard);

        JScrollPane scrollPane = new JScrollPane(contentContainer);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel title = new JLabel("Document Redaction Workspace");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel("Detect sensitive entities, review matches, and export cryptographically sanitized files.");
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

    private JPanel createFileSelectionCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 16));

        JPanel topHeader = ThemeManager.createStepHeader(
                1,
                "Document Selection & Capability Verification",
                "Choose a local document or load a sample document below. The engine verifies file structure and calculates its streaming SHA-256 digest."
        );
        card.add(topHeader, BorderLayout.NORTH);

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.setOpaque(false);

        // Quick practice file loader bar
        JPanel sampleBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        sampleBar.setOpaque(false);
        JLabel samplePrompt = new JLabel("Quick Practice Documents:");
        samplePrompt.setFont(ThemeManager.FONT_SMALL_BOLD);
        samplePrompt.setForeground(ThemeManager.TEXT_SECONDARY);
        sampleBar.add(samplePrompt);

        JButton loadPdfBtn = ThemeManager.createSecondaryButton("📄 Sample Contract (.pdf)");
        loadPdfBtn.setToolTipText("Load pre-configured confidential contract with PII in PDF format");
        loadPdfBtn.addActionListener(e -> loadSampleFile("samples/sample_contract.pdf"));

        JButton loadTxtBtn = ThemeManager.createSecondaryButton("📝 Sample Agreement (.txt)");
        loadTxtBtn.setToolTipText("Load pre-configured text document with sensitive credentials");
        loadTxtBtn.addActionListener(e -> loadSampleFile("samples/sample_contract.txt"));

        JButton loadCsvBtn = ThemeManager.createSecondaryButton("📊 Sample Users (.csv)");
        loadCsvBtn.setToolTipText("Load pre-configured customer records table with PII");
        loadCsvBtn.addActionListener(e -> loadSampleFile("samples/sample_users.csv"));

        sampleBar.add(loadPdfBtn);
        sampleBar.add(loadTxtBtn);
        sampleBar.add(loadCsvBtn);

        centerPanel.add(sampleBar);
        centerPanel.add(Box.createVerticalStrut(10));

        JPanel grid = new JPanel(new GridLayout(2, 3, 14, 8));
        grid.setOpaque(false);

        fileNameLabel = new JLabel("No document selected");
        fileNameLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        fileSizeLabel = new JLabel("-");
        fileSizeLabel.setFont(ThemeManager.FONT_REGULAR);

        fileTypeLabel = new JLabel("-");
        fileTypeLabel.setFont(ThemeManager.FONT_REGULAR);

        fileShaLabel = new JLabel("-");
        fileShaLabel.setFont(ThemeManager.FONT_MONO);

        capabilityStatusBadge = ThemeManager.createBadge("Awaiting File", ThemeManager.CARD_BORDER, ThemeManager.TEXT_MUTED);

        grid.add(createLabeledField("Document Name", fileNameLabel));
        grid.add(createLabeledField("File Size", fileSizeLabel));
        grid.add(createLabeledField("Detected Format", fileTypeLabel));
        grid.add(createLabeledField("Engine Capability", capabilityStatusBadge));
        grid.add(createLabeledField("SHA-256 Digest", fileShaLabel));

        centerPanel.add(grid);
        card.add(centerPanel, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        chooseFileBtn = ThemeManager.createSecondaryButton("Browse Local Document...");
        chooseFileBtn.addActionListener(e -> handleBrowseDocument());

        scanBtn = ThemeManager.createPrimaryButton("Scan Document for Sensitive Data →");
        scanBtn.setEnabled(false);
        scanBtn.addActionListener(e -> handleScanDocument());

        btnRow.add(chooseFileBtn);
        btnRow.add(scanBtn);

        card.add(btnRow, BorderLayout.SOUTH);
        return card;
    }

    private void loadSampleFile(String relativePath) {
        File f = new File(relativePath);
        if (f.exists()) {
            setSelectedDocument(f);
        } else {
            DialogManager.showError(this, "Sample File Error", "Sample file not found at: " + f.getAbsolutePath());
        }
    }

    private JPanel createCandidatesCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JPanel topRow = new JPanel(new BorderLayout(10, 0));
        topRow.setOpaque(false);

        JPanel stepHeader = ThemeManager.createStepHeader(
                2,
                "Sensitive Entity Candidates Review",
                "Review detected PII, credentials, and confidential tokens below. Check the boxes for entities you wish to redact."
        );

        candidateCountLabel = new JLabel("0 candidates detected");
        candidateCountLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);
        candidateCountLabel.setForeground(ThemeManager.PRIMARY_BLUE);

        topRow.add(stepHeader, BorderLayout.CENTER);
        topRow.add(candidateCountLabel, BorderLayout.EAST);
        card.add(topRow, BorderLayout.NORTH);

        scanProgressBar = new JProgressBar();
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setVisible(false);

        String[] columns = {"Apply?", "Candidate Type", "Masked Preview", "Location", "Rule & Confidence"};
        candidateTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        candidateTable = new JTable(candidateTableModel);
        ThemeManager.styleTable(candidateTable);
        candidateTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        candidateTable.getColumnModel().getColumn(1).setPreferredWidth(140);
        candidateTable.getColumnModel().getColumn(2).setPreferredWidth(190);
        candidateTable.getColumnModel().getColumn(3).setPreferredWidth(130);
        candidateTable.getColumnModel().getColumn(4).setPreferredWidth(250);

        candidateTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 0 && e.getFirstRow() >= 0 && e.getFirstRow() < currentMatches.size()) {
                Boolean selected = (Boolean) candidateTableModel.getValueAt(e.getFirstRow(), 0);
                currentMatches.get(e.getFirstRow()).setSelectedForRedaction(selected != null && selected);
                updateSelectedCount();
            }
        });

        JScrollPane tableScroll = new JScrollPane(candidateTable);
        tableScroll.setPreferredSize(new Dimension(0, 200));
        tableScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScroll.getViewport().setBackground(ThemeManager.CARD_BG);

        JPanel tableCenter = new JPanel(new BorderLayout(0, 6));
        tableCenter.setOpaque(false);
        tableCenter.add(scanProgressBar, BorderLayout.NORTH);
        tableCenter.add(tableScroll, BorderLayout.CENTER);
        card.add(tableCenter, BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        bottomRow.setOpaque(false);

        selectAllBtn = ThemeManager.createSecondaryButton("✓ Select All Candidates");
        selectAllBtn.setEnabled(false);
        selectAllBtn.addActionListener(e -> setAllCandidatesSelected(true));

        deselectAllBtn = ThemeManager.createSecondaryButton("✗ Deselect All");
        deselectAllBtn.setEnabled(false);
        deselectAllBtn.addActionListener(e -> setAllCandidatesSelected(false));

        bottomRow.add(selectAllBtn);
        bottomRow.add(deselectAllBtn);
        card.add(bottomRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createExecutionCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JPanel stepHeader = ThemeManager.createStepHeader(
                3,
                "Sanitization Destination & Detached Digital Signing",
                "Specify destination path (never overwrites original). Detached signing creates a cryptographic .zksig proof alongside your file."
        );
        card.add(stepHeader, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 6, 8, 6);

        // Output Path
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel outLbl = new JLabel("Sanitized Destination:");
        outLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(outLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        outputPathField = ThemeManager.createTextField();
        form.add(outputPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        browseOutputBtn = ThemeManager.createSecondaryButton("Choose Location...");
        browseOutputBtn.addActionListener(e -> handleBrowseOutput());
        form.add(browseOutputBtn, gbc);

        // Detached Signing
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        signOutputCheckBox = new JCheckBox("Digitally Sign Sanitized Document (Detached .zksig)");
        signOutputCheckBox.setFont(ThemeManager.FONT_REGULAR_BOLD);
        signOutputCheckBox.setForeground(ThemeManager.TEXT_PRIMARY);
        signOutputCheckBox.setOpaque(false);
        signOutputCheckBox.setSelected(true); // Default to checked for standard security flow
        signOutputCheckBox.addActionListener(e -> keySelectorComboBox.setEnabled(signOutputCheckBox.isSelected()));
        form.add(signOutputCheckBox, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        keySelectorComboBox = ThemeManager.createComboBox();
        refreshKeySelector();
        keySelectorComboBox.setEnabled(true);
        form.add(keySelectorComboBox, gbc);

        card.add(form, BorderLayout.CENTER);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionRow.setOpaque(false);

        applyRedactionBtn = ThemeManager.createPrimaryButton("Confirm & Apply Approved Redactions →");
        applyRedactionBtn.setEnabled(false);
        applyRedactionBtn.addActionListener(e -> handleApplyRedaction());

        actionRow.add(applyRedactionBtn);
        card.add(actionRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createResultCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JPanel stepHeader = ThemeManager.createStepHeader(
                4,
                "Redaction Execution & Cryptographic Digest Summary",
                "The sanitized document has been created and verified. The original file remains completely unaltered."
        );
        card.add(stepHeader, BorderLayout.NORTH);

        JPanel infoGrid = new JPanel(new GridLayout(5, 1, 8, 8));
        infoGrid.setOpaque(false);

        resultStatusLabel = new JLabel("Status: -");
        resultStatusLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        resultOutputLocationLabel = new JLabel("Output: -");
        resultOutputLocationLabel.setFont(ThemeManager.FONT_REGULAR);

        resultCountLabel = new JLabel("Redactions Applied: -");
        resultCountLabel.setFont(ThemeManager.FONT_REGULAR);

        resultHashesLabel = new JLabel("SHA-256 Digests: -");
        resultHashesLabel.setFont(ThemeManager.FONT_MONO);

        resultSignatureLabel = new JLabel("Signature Status: -");
        resultSignatureLabel.setFont(ThemeManager.FONT_REGULAR);

        infoGrid.add(resultStatusLabel);
        infoGrid.add(resultOutputLocationLabel);
        infoGrid.add(resultCountLabel);
        infoGrid.add(resultHashesLabel);
        infoGrid.add(resultSignatureLabel);

        card.add(infoGrid, BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        bottomRow.setOpaque(false);

        JButton verifyNowBtn = ThemeManager.createPrimaryButton("Proceed to Verification Workspace →");
        verifyNowBtn.setToolTipText("Open the Verification workspace with this newly signed document pre-loaded");
        verifyNowBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_VERIFICATION));
        bottomRow.add(verifyNowBtn);

        card.add(bottomRow, BorderLayout.SOUTH);
        return card;
    }

    private JPanel createLabeledField(String title, JComponent comp) {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        p.setOpaque(false);
        JLabel lbl = new JLabel(title);
        lbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        lbl.setForeground(ThemeManager.TEXT_SECONDARY);
        p.add(lbl, BorderLayout.NORTH);
        p.add(comp, BorderLayout.CENTER);
        return p;
    }

    private void handleBrowseDocument() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Document for Scanning & Redaction");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            setSelectedDocument(chooser.getSelectedFile());
        }
    }

    private void setSelectedDocument(File file) {
        this.selectedFile = file;
        Path path = file.toPath();

        DocumentFormat format = context.getDocumentService().detectFormat(path);
        fileNameLabel.setText(file.getName());
        fileSizeLabel.setText(file.length() < 1024 ? file.length() + " B" : (file.length() / 1024) + " KB");
        fileTypeLabel.setText(format.name());

        if (format.isRedactionSupported()) {
            capabilityStatusBadge.setText("Supported (" + format.name() + ")");
            capabilityStatusBadge.setForeground(ThemeManager.SUCCESS_GREEN);
            scanBtn.setEnabled(true);

            try {
                this.documentMetadata = context.getDocumentService().inspectDocument(path);
                String digest = documentMetadata.getSha256Digest();
                fileShaLabel.setText(digest.length() > 24 ? digest.substring(0, 24) + "..." : digest);
            } catch (Exception ex) {
                fileShaLabel.setText("Digest calculation error");
            }

            // Derive safe non-overwriting destination preserving original format extension
            try {
                Path defaultOut = context.getDocumentService().getFileStorageService().resolveDefaultRedactedOutputPath(path);
                outputPathField.setText(defaultOut.toAbsolutePath().toString());
            } catch (Exception ex) {
                String ext = format == DocumentFormat.PDF ? ".pdf" : (format == DocumentFormat.CSV ? ".csv" : ".txt");
                outputPathField.setText(path.toAbsolutePath().toString() + ".redacted" + ext);
            }
        } else {
            capabilityStatusBadge.setText("Unsupported Format");
            capabilityStatusBadge.setForeground(ThemeManager.WARNING_AMBER);
            fileShaLabel.setText("-");
            scanBtn.setEnabled(false);
            DialogManager.showError(this, "Unsupported Document Format",
                    "The selected file format is not supported for redaction. Supported formats: .pdf, .txt, .csv");
        }

        // Reset subsequent steps
        currentMatches.clear();
        candidateTableModel.setRowCount(0);
        candidateCountLabel.setText("0 candidates detected");
        selectAllBtn.setEnabled(false);
        deselectAllBtn.setEnabled(false);
        applyRedactionBtn.setEnabled(false);
        resultCard.setVisible(false);
    }

    private void handleScanDocument() {
        if (selectedFile == null || !selectedFile.exists()) {
            DialogManager.showError(this, "Selection Error", "Please select a valid document first.");
            return;
        }

        scanProgressBar.setVisible(true);
        chooseFileBtn.setEnabled(false);
        scanBtn.setEnabled(false);

        SwingWorker<List<RedactionMatch>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<RedactionMatch> doInBackground() throws Exception {
                return context.getDocumentService().scanDocument(selectedFile.toPath());
            }

            @Override
            protected void done() {
                scanProgressBar.setVisible(false);
                chooseFileBtn.setEnabled(true);
                scanBtn.setEnabled(true);

                try {
                    currentMatches = get();
                    candidateTableModel.setRowCount(0);

                    if (currentMatches.isEmpty()) {
                        candidateCountLabel.setText("No sensitive candidates detected");
                        selectAllBtn.setEnabled(false);
                        deselectAllBtn.setEnabled(false);
                        applyRedactionBtn.setEnabled(false);
                        DialogManager.showInfo(RedactionPanel.this, "Scan Complete",
                                "No sensitive PII, credentials, or targeted patterns were detected.");
                    } else {
                        for (RedactionMatch m : currentMatches) {
                            String loc = (m.getRowIndex() >= 0)
                                    ? "Row " + (m.getRowIndex() + 1) + ", Col " + (m.getColumnIndex() + 1)
                                    : "Offset " + m.getStartOffset() + "-" + m.getEndOffset();

                            candidateTableModel.addRow(new Object[]{
                                    m.isSelectedForRedaction(),
                                    m.getCandidateType(),
                                    m.getMaskedPreview(),
                                    loc,
                                    m.getRuleId() + " (" + (int)(m.getConfidence() * 100) + "%)"
                            });
                        }
                        selectAllBtn.setEnabled(true);
                        deselectAllBtn.setEnabled(true);
                        updateSelectedCount();
                    }
                } catch (Exception ex) {
                    DialogManager.showError(RedactionPanel.this, "Scan Error",
                            "Failed to scan document: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    private void handleBrowseOutput() {
        JFileChooser chooser = new JFileChooser();
        if (!outputPathField.getText().trim().isEmpty()) {
            chooser.setSelectedFile(new File(outputPathField.getText().trim()));
        }
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            outputPathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void setAllCandidatesSelected(boolean selected) {
        for (int i = 0; i < candidateTableModel.getRowCount(); i++) {
            candidateTableModel.setValueAt(selected, i, 0);
        }
        for (RedactionMatch m : currentMatches) {
            m.setSelectedForRedaction(selected);
        }
        updateSelectedCount();
    }

    private void updateSelectedCount() {
        int selectedCount = 0;
        for (RedactionMatch m : currentMatches) {
            if (m.isSelectedForRedaction()) selectedCount++;
        }
        candidateCountLabel.setText(selectedCount + " of " + currentMatches.size() + " selected for redaction");
        applyRedactionBtn.setEnabled(selectedCount > 0);
    }

    private void handleApplyRedaction() {
        if (selectedFile == null) return;

        String outPath = outputPathField.getText().trim();
        if (outPath.isEmpty()) {
            DialogManager.showError(this, "Destination Error", "Please provide a valid output file path.");
            return;
        }

        File outFile = new File(outPath);
        if (outFile.getAbsolutePath().equals(selectedFile.getAbsolutePath())) {
            DialogManager.showError(this, "Safety Violation",
                    "Redacted output cannot overwrite the original source document. Please choose a distinct filename.");
            return;
        }

        long approvedCount = currentMatches.stream().filter(RedactionMatch::isSelectedForRedaction).count();
        boolean confirm = DialogManager.showConfirmation(this, "Confirm Redaction",
                "Apply " + approvedCount + " approved redaction(s) to create:\n" + outFile.getName() +
                        "\n\nOriginal file will remain unaltered.", "Apply Redaction");
        if (!confirm) return;

        boolean sign = signOutputCheckBox.isSelected();
        KeyPair signingKeyPair = null;
        if (sign) {
            String selectedAlias = (String) keySelectorComboBox.getSelectedItem();
            if (selectedAlias == null || selectedAlias.isEmpty()) {
                DialogManager.showError(this, "Signing Error", "No RSA key selected for digital signing.");
                return;
            }
            signingKeyPair = context.getSessionKeyPairs().get(selectedAlias);
            if (signingKeyPair == null) {
                DialogManager.showError(this, "Signing Error",
                        "The selected key '" + selectedAlias + "' is not present in the current session.");
                return;
            }
        }

        applyRedactionBtn.setEnabled(false);
        final KeyPair finalKey = signingKeyPair;

        SwingWorker<RedactionResult, Void> worker = new SwingWorker<>() {
            private Path signaturePathCreated = null;

            @Override
            protected RedactionResult doInBackground() throws Exception {
                RedactionResult result = context.getDocumentService().applyApprovedRedactions(
                        selectedFile.toPath(),
                        outFile.toPath(),
                        currentMatches
                );

                if (result.isSuccess() && sign && finalKey != null) {
                    Path sigFile = context.getDocumentService().getFileStorageService()
                            .resolveDefaultSignaturePath(outFile.toPath());
                    context.getSignatureService().signAndSaveDetached(
                            outFile.toPath(),
                            finalKey.getPrivate(),
                            finalKey.getPublic(),
                            sigFile
                    );
                    signaturePathCreated = sigFile;
                }

                return result;
            }

            @Override
            protected void done() {
                applyRedactionBtn.setEnabled(true);
                try {
                    RedactionResult result = get();
                    if (result.isSuccess()) {
                        context.setLastRedactedDocumentPath(result.getOutputPath());
                        if (signaturePathCreated != null) {
                            context.setLastSignaturePath(signaturePathCreated);
                        }

                        resultCard.setVisible(true);
                        resultStatusLabel.setText("Status: Redaction Succeeded");
                        resultStatusLabel.setForeground(ThemeManager.SUCCESS_GREEN);

                        resultOutputLocationLabel.setText("Output: " + result.getOutputPath().toAbsolutePath());
                        resultCountLabel.setText("Redactions Applied: " + result.getApprovedMatchesApplied() + " candidate(s) sanitized");
                        resultHashesLabel.setText("<html>Source SHA-256: <code>" + result.getSourceSha256() +
                                "</code><br>Output SHA-256: <code>" + result.getOutputSha256() + "</code></html>");

                        if (signaturePathCreated != null) {
                            resultSignatureLabel.setText("Signature: Detached .zksig created at " + signaturePathCreated.toAbsolutePath());
                            resultSignatureLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                        } else {
                            resultSignatureLabel.setText("Signature: Not digitally signed");
                            resultSignatureLabel.setForeground(ThemeManager.TEXT_SECONDARY);
                        }

                        DialogManager.showInfo(RedactionPanel.this, "Redaction Complete",
                                "Sanitized document created successfully at:\n" + outFile.getAbsolutePath() +
                                        (signaturePathCreated != null ? "\n\nDetached signature generated." : ""));
                    } else {
                        DialogManager.showError(RedactionPanel.this, "Redaction Failed", result.getSummaryMessage());
                    }
                } catch (Exception e) {
                    DialogManager.showError(RedactionPanel.this, "Execution Error",
                            "Failed to apply redactions: " + e.getMessage());
                }
            }
        };

        worker.execute();
    }

    public void refreshKeySelector() {
        keySelectorComboBox.removeAllItems();
        Map<String, KeyPair> keys = context.getSessionKeyPairs();
        for (String alias : keys.keySet()) {
            keySelectorComboBox.addItem(alias);
        }
        if (keySelectorComboBox.getItemCount() > 0) {
            keySelectorComboBox.setSelectedIndex(0);
        }
    }
}
