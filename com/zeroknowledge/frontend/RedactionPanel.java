package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.model.KeyInfo;
import com.zeroknowledge.model.OperationRecord;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import core.DocumentMetaData;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * 5-Step Redaction Workspace:
 * 1. Document Selection & Capability Check
 * 2. Background Sensitive Data Scanning
 * 3. Review & Selection of Candidates
 * 4. Destination & Signing Configuration
 * 5. Redaction Execution & Verification Summary
 */
public class RedactionPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    // State
    private File selectedFile;
    private DocumentMetaData documentMetaData;
    private List<RedactionMatch> currentMatches = new ArrayList<>();

    // UI Components - Step 1: File selection
    private JLabel fileNameLabel;
    private JLabel fileSizeLabel;
    private JLabel fileTypeLabel;
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
    private JTextArea previewTextArea;

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
        // Main container with vertical scroll
        JPanel contentContainer = new JPanel();
        contentContainer.setLayout(new BoxLayout(contentContainer, BoxLayout.Y_AXIS));
        contentContainer.setOpaque(false);

        // Header Panel
        contentContainer.add(createHeaderPanel());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 1: File Selection & Metadata Card
        contentContainer.add(createFileSelectionCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 2 & 3: Scan & Candidates Review Card
        contentContainer.add(createCandidatesCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 4: Redaction & Signing Configuration Card
        contentContainer.add(createExecutionCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Step 5: Result Summary Card
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

        JLabel title = new JLabel("Redaction Workspace");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel("Detect sensitive entities, verify redaction rules, and export cryptographically sanitized files.");
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
        card.setLayout(new BorderLayout(0, 12));

        JLabel stepLabel = new JLabel("STEP 1: Document Selection & Capability Verification");
        stepLabel.setFont(ThemeManager.FONT_HEADER);
        stepLabel.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(stepLabel, BorderLayout.NORTH);

        // File Details Grid
        JPanel grid = new JPanel(new GridLayout(2, 3, 14, 8));
        grid.setOpaque(false);

        fileNameLabel = new JLabel("No document selected");
        fileNameLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        fileSizeLabel = new JLabel("-");
        fileSizeLabel.setFont(ThemeManager.FONT_REGULAR);

        fileTypeLabel = new JLabel("-");
        fileTypeLabel.setFont(ThemeManager.FONT_REGULAR);

        capabilityStatusBadge = ThemeManager.createBadge("Awaiting File", ThemeManager.CARD_BORDER, ThemeManager.TEXT_MUTED);

        grid.add(createLabeledField("Document Name", fileNameLabel));
        grid.add(createLabeledField("File Size", fileSizeLabel));
        grid.add(createLabeledField("Format / Extension", fileTypeLabel));
        grid.add(createLabeledField("Engine Capability", capabilityStatusBadge));

        card.add(grid, BorderLayout.CENTER);

        // Action Buttons Row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        chooseFileBtn = ThemeManager.createSecondaryButton("Browse Document...");
        chooseFileBtn.addActionListener(e -> handleBrowseDocument());

        scanBtn = ThemeManager.createPrimaryButton("Scan Document");
        scanBtn.setEnabled(false);
        scanBtn.addActionListener(e -> handleScanDocument());

        btnRow.add(chooseFileBtn);
        btnRow.add(scanBtn);

        card.add(btnRow, BorderLayout.SOUTH);
        return card;
    }

    private JPanel createCandidatesCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.setOpaque(false);

        JLabel stepLabel = new JLabel("STEPS 2 & 3: Sensitive Data Candidates");
        stepLabel.setFont(ThemeManager.FONT_HEADER);
        stepLabel.setForeground(ThemeManager.TEXT_PRIMARY);

        candidateCountLabel = new JLabel("0 candidates detected");
        candidateCountLabel.setFont(ThemeManager.FONT_REGULAR);
        candidateCountLabel.setForeground(ThemeManager.TEXT_SECONDARY);

        topRow.add(stepLabel, BorderLayout.WEST);
        topRow.add(candidateCountLabel, BorderLayout.EAST);
        card.add(topRow, BorderLayout.NORTH);

        // Scan Progress bar (hidden by default)
        scanProgressBar = new JProgressBar();
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setVisible(false);

        // Candidate JTable
        String[] columns = {"Apply?", "ID", "Type", "Masked Preview", "Location", "Detection Rule"};
        candidateTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only checkbox is editable
            }
        };

        candidateTable = new JTable(candidateTableModel);
        ThemeManager.styleTable(candidateTable);
        candidateTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        candidateTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        candidateTable.getColumnModel().getColumn(2).setPreferredWidth(120);
        candidateTable.getColumnModel().getColumn(3).setPreferredWidth(180);
        candidateTable.getColumnModel().getColumn(4).setPreferredWidth(120);
        candidateTable.getColumnModel().getColumn(5).setPreferredWidth(260);

        // Checkbox listener to update candidate selected state
        candidateTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 0 && e.getFirstRow() >= 0 && e.getFirstRow() < currentMatches.size()) {
                Boolean selected = (Boolean) candidateTableModel.getValueAt(e.getFirstRow(), 0);
                currentMatches.get(e.getFirstRow()).setSelected(selected != null && selected);
                updateSelectedCount();
            }
        });

        JScrollPane tableScroll = new JScrollPane(candidateTable);
        tableScroll.setPreferredSize(new Dimension(0, 180));
        tableScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScroll.getViewport().setBackground(ThemeManager.CARD_BG);

        JPanel tableCenter = new JPanel(new BorderLayout(0, 6));
        tableCenter.setOpaque(false);
        tableCenter.add(scanProgressBar, BorderLayout.NORTH);
        tableCenter.add(tableScroll, BorderLayout.CENTER);
        card.add(tableCenter, BorderLayout.CENTER);

        // Selection Controls Row
        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        bottomRow.setOpaque(false);

        selectAllBtn = ThemeManager.createSecondaryButton("Select All");
        selectAllBtn.setEnabled(false);
        selectAllBtn.addActionListener(e -> setAllCandidatesSelected(true));

        deselectAllBtn = ThemeManager.createSecondaryButton("Deselect All");
        deselectAllBtn.setEnabled(false);
        deselectAllBtn.addActionListener(e -> setAllCandidatesSelected(false));

        bottomRow.add(selectAllBtn);
        bottomRow.add(deselectAllBtn);
        card.add(bottomRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createExecutionCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel stepLabel = new JLabel("STEP 4: Output Destination & Cryptographic Signature");
        stepLabel.setFont(ThemeManager.FONT_HEADER);
        stepLabel.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(stepLabel, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 4, 6, 4);

        // Output Path
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel outLbl = new JLabel("Sanitized Output Path:");
        outLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(outLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        outputPathField = new JTextField();
        outputPathField.setFont(ThemeManager.FONT_REGULAR);
        form.add(outputPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        browseOutputBtn = ThemeManager.createSecondaryButton("Choose Destination...");
        browseOutputBtn.addActionListener(e -> handleBrowseOutput());
        form.add(browseOutputBtn, gbc);

        // Digital Signing
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        signOutputCheckBox = new JCheckBox("Digitally Sign Redacted Document (Detached RSA Signature)");
        signOutputCheckBox.setFont(ThemeManager.FONT_REGULAR_BOLD);
        signOutputCheckBox.setOpaque(false);
        signOutputCheckBox.addActionListener(e -> keySelectorComboBox.setEnabled(signOutputCheckBox.isSelected()));
        form.add(signOutputCheckBox, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        keySelectorComboBox = new JComboBox<>();
        keySelectorComboBox.setFont(ThemeManager.FONT_SMALL);
        keySelectorComboBox.setEnabled(false);
        refreshKeySelector();
        form.add(keySelectorComboBox, gbc);

        card.add(form, BorderLayout.CENTER);

        // Action Row
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionRow.setOpaque(false);

        applyRedactionBtn = ThemeManager.createPrimaryButton("Confirm & Apply Redaction");
        applyRedactionBtn.setEnabled(false);
        applyRedactionBtn.addActionListener(e -> handleApplyRedaction());

        actionRow.add(applyRedactionBtn);
        card.add(actionRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createResultCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel stepLabel = new JLabel("STEP 5: Redaction Execution Results");
        stepLabel.setFont(ThemeManager.FONT_HEADER);
        stepLabel.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(stepLabel, BorderLayout.NORTH);

        JPanel infoGrid = new JPanel(new GridLayout(5, 1, 6, 6));
        infoGrid.setOpaque(false);

        resultStatusLabel = new JLabel("Status: -");
        resultStatusLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        resultOutputLocationLabel = new JLabel("Output: -");
        resultOutputLocationLabel.setFont(ThemeManager.FONT_REGULAR);

        resultCountLabel = new JLabel("Redactions Applied: -");
        resultCountLabel.setFont(ThemeManager.FONT_REGULAR);

        resultHashesLabel = new JLabel("Cryptographic Digests (SHA-256): -");
        resultHashesLabel.setFont(ThemeManager.FONT_MONO);

        resultSignatureLabel = new JLabel("Signature Status: -");
        resultSignatureLabel.setFont(ThemeManager.FONT_REGULAR);

        infoGrid.add(resultStatusLabel);
        infoGrid.add(resultOutputLocationLabel);
        infoGrid.add(resultCountLabel);
        infoGrid.add(resultHashesLabel);
        infoGrid.add(resultSignatureLabel);

        card.add(infoGrid, BorderLayout.CENTER);
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
            File f = chooser.getSelectedFile();
            setSelectedDocument(f);
        }
    }

    private void setSelectedDocument(File file) {
        this.selectedFile = file;
        this.documentMetaData = new DocumentMetaData(file);

        fileNameLabel.setText(documentMetaData.getFileName());
        fileSizeLabel.setText(documentMetaData.getFormattedSize());
        fileTypeLabel.setText(documentMetaData.getFileExtension().toUpperCase());

        // Check backend capability
        if (context.getRedactionService().isPdf(file)) {
            capabilityStatusBadge.setText("Unsupported (PDF)");
            capabilityStatusBadge.setForeground(ThemeManager.DANGER_RED);
            scanBtn.setEnabled(false);
            DialogManager.showWarning(this, "PDF Format Limitation",
                    context.getRedactionService().getPdfLimitationExplanation());
        } else if (context.getRedactionService().isSupportedForRedaction(file)) {
            capabilityStatusBadge.setText("Supported Format");
            capabilityStatusBadge.setForeground(ThemeManager.SUCCESS_GREEN);
            scanBtn.setEnabled(true);

            // Suggest default output path (never overwriting the original)
            String dir = context.getConfigService().getOutputDirectory();
            String name = file.getName();
            int dot = name.lastIndexOf('.');
            String base = (dot > 0) ? name.substring(0, dot) : name;
            String ext = (dot > 0) ? name.substring(dot) : ".txt";
            File defOut = new File(dir, base + "_redacted" + ext);
            outputPathField.setText(defOut.getAbsolutePath());
        } else {
            capabilityStatusBadge.setText("Unsupported Format");
            capabilityStatusBadge.setForeground(ThemeManager.WARNING_AMBER);
            scanBtn.setEnabled(false);
            DialogManager.showError(this, "Unsupported Format",
                    "Format '" + documentMetaData.getFileExtension() + "' is not supported. Supported: txt, csv, log, json, md");
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

        // Run scanning via SwingWorker
        SwingWorker<List<RedactionMatch>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<RedactionMatch> doInBackground() throws Exception {
                Set<String> enabledPatterns = context.getConfigService().getEnabledPatterns();
                return context.getRedactionService().scanDocument(selectedFile, enabledPatterns);
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
                                "No sensitive PII, credentials, or sensitive patterns were detected with the current rules.");

                        context.getAuditService().logOperation(
                                OperationRecord.OperationType.SCAN,
                                selectedFile.getName(),
                                OperationRecord.Status.SUCCESS,
                                "Scan completed with 0 matches found"
                        );
                    } else {
                        for (RedactionMatch m : currentMatches) {
                            candidateTableModel.addRow(new Object[]{
                                    m.isSelected(),
                                    m.getId(),
                                    m.getCandidateType(),
                                    m.getMaskedPreview(),
                                    m.getLocationDisplay(),
                                    m.getRuleDescription()
                            });
                        }
                        selectAllBtn.setEnabled(true);
                        deselectAllBtn.setEnabled(true);
                        applyRedactionBtn.setEnabled(true);
                        updateSelectedCount();

                        context.getAuditService().logOperation(
                                OperationRecord.OperationType.SCAN,
                                selectedFile.getName(),
                                OperationRecord.Status.SUCCESS,
                                "Scan detected " + currentMatches.size() + " sensitive candidate(s)"
                        );
                    }
                } catch (Exception ex) {
                    DialogManager.showError(RedactionPanel.this, "Scan Failed",
                            "An error occurred while scanning: " + ex.getMessage());
                    context.getAuditService().logOperation(
                            OperationRecord.OperationType.SCAN,
                            selectedFile.getName(),
                            OperationRecord.Status.FAILED,
                            "Scan error: " + ex.getMessage()
                    );
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
            m.setSelected(selected);
        }
        updateSelectedCount();
    }

    private void updateSelectedCount() {
        int selectedCount = 0;
        for (RedactionMatch m : currentMatches) {
            if (m.isSelected()) selectedCount++;
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
            DialogManager.showError(this, "Policy Violation",
                    "Redacted output cannot overwrite the original document. Please choose a distinct filename.");
            return;
        }

        // Confirmation step
        long approvedCount = currentMatches.stream().filter(RedactionMatch::isSelected).count();
        boolean confirm = DialogManager.showConfirmation(this, "Confirm Redaction",
                "Apply " + approvedCount + " approved redaction(s) to create:\n" + outFile.getName() +
                        "\n\nOriginal file will remain untouched.", "Apply Redaction");
        if (!confirm) {
            context.getAuditService().logOperation(
                    OperationRecord.OperationType.REDACT,
                    selectedFile.getName(),
                    OperationRecord.Status.CANCELLED,
                    "Redaction execution cancelled by user"
            );
            return;
        }

        boolean sign = signOutputCheckBox.isSelected();
        KeyPair signingKeyPair = null;
        if (sign) {
            String selectedAlias = (String) keySelectorComboBox.getSelectedItem();
            if (selectedAlias == null || selectedAlias.isEmpty()) {
                DialogManager.showError(this, "Signing Error", "No RSA key selected for digital signing.");
                return;
            }
            signingKeyPair = context.getCryptoService().getKeyPair(selectedAlias);
            if (signingKeyPair == null) {
                DialogManager.showError(this, "Signing Error",
                        "The selected key '" + selectedAlias + "' is not available in memory for signing.");
                return;
            }
        }

        applyRedactionBtn.setEnabled(false);
        final KeyPair finalKey = signingKeyPair;

        SwingWorker<RedactionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected RedactionResult doInBackground() throws Exception {
                return context.getRedactionService().applyRedaction(
                        selectedFile,
                        outFile,
                        currentMatches,
                        sign,
                        finalKey,
                        context.getCryptoService()
                );
            }

            @Override
            protected void done() {
                applyRedactionBtn.setEnabled(true);
                try {
                    RedactionResult result = get();
                    if (result.isSuccess()) {
                        resultCard.setVisible(true);
                        resultStatusLabel.setText("Status: Redaction Succeeded");
                        resultStatusLabel.setForeground(ThemeManager.SUCCESS_GREEN);

                        resultOutputLocationLabel.setText("Output: " + result.getOutputFilePath());
                        resultCountLabel.setText("Redactions Applied: " + result.getCandidatesRedacted() +
                                " entity/entities sanitized");
                        resultHashesLabel.setText("<html>Original SHA-256: <code>" + result.getOriginalFileSha256() +
                                "</code><br>Redacted SHA-256: <code>" + result.getRedactedFileSha256() + "</code></html>");

                        if (result.isSigned()) {
                            resultSignatureLabel.setText("Signature: Detached RSA signature created at " + result.getSignaturePath());
                            resultSignatureLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                        } else {
                            resultSignatureLabel.setText("Signature: Not digitally signed");
                            resultSignatureLabel.setForeground(ThemeManager.TEXT_SECONDARY);
                        }

                        context.getAuditService().logOperation(
                                OperationRecord.OperationType.REDACT,
                                selectedFile.getName(),
                                OperationRecord.Status.SUCCESS,
                                "Applied " + result.getCandidatesRedacted() + " redactions -> " + outFile.getName() +
                                        (result.isSigned() ? " (Digitally Signed)" : "")
                        );

                        DialogManager.showInfo(RedactionPanel.this, "Redaction Complete",
                                "Sanitized document created successfully at:\n" + outFile.getAbsolutePath() +
                                        (result.isSigned() ? "\n\nDetached signature generated." : ""));
                    } else {
                        DialogManager.showError(RedactionPanel.this, "Redaction Failed", result.getErrorMessage());
                        context.getAuditService().logOperation(
                                OperationRecord.OperationType.REDACT,
                                selectedFile.getName(),
                                OperationRecord.Status.FAILED,
                                "Redaction failed: " + result.getErrorMessage()
                        );
                    }
                } catch (Exception e) {
                    DialogManager.showError(RedactionPanel.this, "Error", "Execution failed: " + e.getMessage());
                }
            }
        };

        worker.execute();
    }

    public void refreshKeySelector() {
        keySelectorComboBox.removeAllItems();
        List<KeyInfo> keys = context.getCryptoService().getAvailableKeyInfos();
        for (KeyInfo k : keys) {
            if (k.isPrivateKeyAvailable()) {
                keySelectorComboBox.addItem(k.getAlias());
            }
        }
        if (keySelectorComboBox.getItemCount() > 0) {
            keySelectorComboBox.setSelectedIndex(0);
        }
    }
}
