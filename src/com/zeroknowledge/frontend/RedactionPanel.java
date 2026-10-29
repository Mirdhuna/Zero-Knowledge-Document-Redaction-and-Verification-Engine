package com.zeroknowledge.frontend;

import com.zeroknowledge.document.DocumentFormat;
import com.zeroknowledge.document.TesseractOcrEngine;
import com.zeroknowledge.model.DocumentMetadata;
import com.zeroknowledge.model.DocumentScanReport;
import com.zeroknowledge.model.DocumentScanReport.ScanOutcome;
import com.zeroknowledge.model.PageExtractionReport;
import com.zeroknowledge.model.RedactionMatch;
import com.zeroknowledge.model.RedactionResult;
import com.zeroknowledge.model.RedactionResult.VerificationStatus;

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
 * 2. Page-by-Page Native Text & OCR Extraction Status + Background Sensitive Data Scanning
 * 3. Review & Selection of Candidates (with Page, Bounding Box Coordinates, Confidence, and Manual Review flags)
 * 4. Destination & Detached Signing Configuration
 * 5. Redaction Execution, Independent Verification Status (VERIFIED / PARTIAL / FAILED), & Cryptographic Summary
 */
public class RedactionPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    // State
    private File selectedFile;
    private DocumentMetadata documentMetadata;
    private DocumentScanReport currentScanReport;
    private List<RedactionMatch> currentMatches = new ArrayList<>();
    private boolean suppressTableListener = false;

    // UI Components - Step 1: File selection
    private JLabel fileNameLabel;
    private JLabel fileSizeLabel;
    private JLabel fileTypeLabel;
    private JLabel fileShaLabel;
    private JLabel capabilityStatusBadge;
    private JButton chooseFileBtn;
    private JButton scanBtn;

    // UI Components - Step 2: Extraction & OCR Status Summary
    private JLabel scanOutcomeBadge;
    private JLabel pagesProcessedLabel;
    private JLabel pagesFailedLabel;
    private JLabel ocrStatusLabel;
    private JTextArea perPageStatusArea;
    private JButton ocrSetupBtn;

    // UI Components - Step 2 & 3: Candidates Table
    private JTable candidateTable;
    private DefaultTableModel candidateTableModel;
    private JButton selectAllBtn;
    private JButton selectHighConfBtn;
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
    private JLabel resultVerificationStatusLabel;
    private JLabel resultOutputLocationLabel;
    private JLabel resultCountLabel;
    private JLabel resultVerificationReportLabel;
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

        // Steps 2 & 3: Extraction Status, Scan & Candidates Review
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

        JLabel desc = new JLabel("Extract native & OCR text page-by-page, review sensitive matches, permanently redact PDF/TXT/CSV files, and verify outputs.");
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
                "Page Extraction Diagnostics & Sensitive Entity Candidates Review",
                "Inspect per-page native/OCR extraction status, review detected PII candidates with coordinates, and select items to redact."
        );

        candidateCountLabel = new JLabel("0 candidates detected");
        candidateCountLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);
        candidateCountLabel.setForeground(ThemeManager.PRIMARY_BLUE);

        topRow.add(stepHeader, BorderLayout.CENTER);
        topRow.add(candidateCountLabel, BorderLayout.EAST);
        card.add(topRow, BorderLayout.NORTH);

        // Extraction & OCR Status Panel
        JPanel extractionSummaryPanel = new JPanel(new BorderLayout(10, 8));
        extractionSummaryPanel.setBackground(new Color(248, 250, 252));
        extractionSummaryPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ThemeManager.CARD_BORDER),
                new EmptyBorder(10, 12, 10, 12)
        ));

        JPanel statsGrid = new JPanel(new GridLayout(1, 4, 12, 4));
        statsGrid.setOpaque(false);

        scanOutcomeBadge = ThemeManager.createBadge("Not Scanned", ThemeManager.CARD_BORDER, ThemeManager.TEXT_MUTED);
        pagesProcessedLabel = new JLabel("Pages Processed: -");
        pagesProcessedLabel.setFont(ThemeManager.FONT_SMALL_BOLD);
        pagesFailedLabel = new JLabel("Pages Failed: -");
        pagesFailedLabel.setFont(ThemeManager.FONT_SMALL_BOLD);
        ocrStatusLabel = new JLabel("OCR Engine: Ready");
        ocrStatusLabel.setFont(ThemeManager.FONT_SMALL);

        statsGrid.add(createLabeledField("Extraction Outcome", scanOutcomeBadge));
        statsGrid.add(createLabeledField("Pages Processed", pagesProcessedLabel));
        statsGrid.add(createLabeledField("Failed Pages", pagesFailedLabel));
        statsGrid.add(createLabeledField("Local OCR Status", ocrStatusLabel));

        perPageStatusArea = new JTextArea(3, 60);
        perPageStatusArea.setEditable(false);
        perPageStatusArea.setFont(ThemeManager.FONT_MONO);
        perPageStatusArea.setBackground(new Color(241, 245, 249));
        perPageStatusArea.setForeground(ThemeManager.TEXT_PRIMARY);
        perPageStatusArea.setText("Per-page native and OCR extraction status will appear here after scanning.");
        JScrollPane pageStatusScroll = new JScrollPane(perPageStatusArea);
        pageStatusScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));

        JPanel ocrBtnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        ocrBtnPanel.setOpaque(false);
        ocrSetupBtn = ThemeManager.createSecondaryButton("OCR Setup Instructions");
        ocrSetupBtn.setToolTipText("View local Tesseract OCR installation and language pack setup instructions");
        ocrSetupBtn.addActionListener(e -> showOcrSetupInstructionsDialog());
        ocrBtnPanel.add(ocrSetupBtn);

        extractionSummaryPanel.add(statsGrid, BorderLayout.NORTH);
        extractionSummaryPanel.add(pageStatusScroll, BorderLayout.CENTER);
        extractionSummaryPanel.add(ocrBtnPanel, BorderLayout.SOUTH);

        scanProgressBar = new JProgressBar();
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setVisible(false);

        String[] columns = {
                "Apply?",
                "Category",
                "Masked Preview",
                "Page & Region Coordinates",
                "Method & Confidence",
                "Status & Review Reason"
        };
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
        candidateTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        candidateTable.getColumnModel().getColumn(1).setPreferredWidth(125);
        candidateTable.getColumnModel().getColumn(2).setPreferredWidth(155);
        candidateTable.getColumnModel().getColumn(3).setPreferredWidth(195);
        candidateTable.getColumnModel().getColumn(4).setPreferredWidth(135);
        candidateTable.getColumnModel().getColumn(5).setPreferredWidth(250);

        candidateTableModel.addTableModelListener(e -> {
            if (suppressTableListener) return;
            if (e.getColumn() == 0 && e.getFirstRow() >= 0 && e.getFirstRow() < currentMatches.size()) {
                int row = e.getFirstRow();
                Boolean selected = (Boolean) candidateTableModel.getValueAt(row, 0);
                RedactionMatch match = currentMatches.get(row);
                if (Boolean.TRUE.equals(selected) && !match.canBeSafelyRedacted()) {
                    suppressTableListener = true;
                    candidateTableModel.setValueAt(false, row, 0);
                    suppressTableListener = false;
                    DialogManager.showWarning(this, "Unmapped Coordinates",
                            "This candidate (" + match.getCandidateType() + " on Page " + match.getPageNumber()
                                    + ") could not be mapped to reliable source coordinates and cannot be safely redacted automatically.");
                    return;
                }
                match.setSelectedForRedaction(selected != null && selected);
                updateSelectedCount();
            }
        });

        JScrollPane tableScroll = new JScrollPane(candidateTable);
        tableScroll.setPreferredSize(new Dimension(0, 210));
        tableScroll.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScroll.getViewport().setBackground(ThemeManager.CARD_BG);

        JPanel centerStack = new JPanel(new BorderLayout(0, 8));
        centerStack.setOpaque(false);
        JPanel topProgressAndSummary = new JPanel(new BorderLayout(0, 6));
        topProgressAndSummary.setOpaque(false);
        topProgressAndSummary.add(scanProgressBar, BorderLayout.NORTH);
        topProgressAndSummary.add(extractionSummaryPanel, BorderLayout.CENTER);

        centerStack.add(topProgressAndSummary, BorderLayout.NORTH);
        centerStack.add(tableScroll, BorderLayout.CENTER);
        card.add(centerStack, BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        bottomRow.setOpaque(false);

        selectAllBtn = ThemeManager.createSecondaryButton("✓ Select All Redactable");
        selectAllBtn.setEnabled(false);
        selectAllBtn.addActionListener(e -> setCandidatesSelected(true, false));

        selectHighConfBtn = ThemeManager.createSecondaryButton("✓ Select Verified Ready Only");
        selectHighConfBtn.setToolTipText("Select only candidates with REDACTABLE status that do not require manual review");
        selectHighConfBtn.setEnabled(false);
        selectHighConfBtn.addActionListener(e -> setCandidatesSelected(true, true));

        deselectAllBtn = ThemeManager.createSecondaryButton("✗ Deselect All");
        deselectAllBtn.setEnabled(false);
        deselectAllBtn.addActionListener(e -> setCandidatesSelected(false, false));

        bottomRow.add(selectAllBtn);
        bottomRow.add(selectHighConfBtn);
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
        signOutputCheckBox.setSelected(true);
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
                "Redaction Execution, Independent Verification & Cryptographic Summary",
                "The output document was reopened and independently inspected for text and image redaction completeness."
        );
        card.add(stepHeader, BorderLayout.NORTH);

        JPanel infoGrid = new JPanel(new GridLayout(6, 1, 8, 8));
        infoGrid.setOpaque(false);

        resultStatusLabel = new JLabel("Execution Status: -");
        resultStatusLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        resultVerificationStatusLabel = new JLabel("Final Verification Status: -");
        resultVerificationStatusLabel.setFont(ThemeManager.FONT_REGULAR_BOLD);

        resultOutputLocationLabel = new JLabel("Output File Path: -");
        resultOutputLocationLabel.setFont(ThemeManager.FONT_REGULAR);

        resultCountLabel = new JLabel("Redaction Counts: -");
        resultCountLabel.setFont(ThemeManager.FONT_REGULAR);

        resultVerificationReportLabel = new JLabel("Verification Report: -");
        resultVerificationReportLabel.setFont(ThemeManager.FONT_SMALL);

        resultHashesLabel = new JLabel("SHA-256 Digests: -");
        resultHashesLabel.setFont(ThemeManager.FONT_MONO);

        resultSignatureLabel = new JLabel("Signature Status: -");
        resultSignatureLabel.setFont(ThemeManager.FONT_REGULAR);

        infoGrid.add(resultStatusLabel);
        infoGrid.add(resultVerificationStatusLabel);
        infoGrid.add(resultOutputLocationLabel);
        infoGrid.add(resultCountLabel);
        infoGrid.add(resultVerificationReportLabel);
        infoGrid.add(resultHashesLabel);

        JPanel centerWrap = new JPanel(new BorderLayout(0, 8));
        centerWrap.setOpaque(false);
        centerWrap.add(infoGrid, BorderLayout.CENTER);
        centerWrap.add(resultSignatureLabel, BorderLayout.SOUTH);

        card.add(centerWrap, BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        bottomRow.setOpaque(false);

        JButton verifyNowBtn = ThemeManager.createPrimaryButton("Proceed to Cryptographic Verification Workspace →");
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

    private void showOcrSetupInstructionsDialog() {
        String instructions = TesseractOcrEngine.SETUP_INSTRUCTIONS;
        JTextArea textArea = new JTextArea(instructions, 16, 62);
        textArea.setEditable(false);
        textArea.setFont(ThemeManager.FONT_MONO);
        textArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(textArea);
        JOptionPane.showMessageDialog(
                this,
                scrollPane,
                "Local Tesseract OCR Setup Instructions",
                JOptionPane.INFORMATION_MESSAGE
        );
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
        this.currentScanReport = null;
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
                fileShaLabel.setText("Validation/Digest Error");
                capabilityStatusBadge.setText("Malformed / Unreadable " + format.name());
                capabilityStatusBadge.setForeground(ThemeManager.DANGER_RED);
            }

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
        suppressTableListener = true;
        candidateTableModel.setRowCount(0);
        suppressTableListener = false;
        candidateCountLabel.setText("0 candidates detected");
        scanOutcomeBadge.setText("Awaiting Scan");
        scanOutcomeBadge.setForeground(ThemeManager.TEXT_MUTED);
        pagesProcessedLabel.setText("Pages Processed: -");
        pagesFailedLabel.setText("Pages Failed: -");
        pagesFailedLabel.setForeground(ThemeManager.TEXT_PRIMARY);
        ocrStatusLabel.setText("OCR Engine: Ready");
        perPageStatusArea.setText("Click 'Scan Document for Sensitive Data' to extract pages and detect sensitive entities.");
        selectAllBtn.setEnabled(false);
        selectHighConfBtn.setEnabled(false);
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

        SwingWorker<DocumentScanReport, Void> worker = new SwingWorker<>() {
            @Override
            protected DocumentScanReport doInBackground() throws Exception {
                return context.getDocumentService().scanDocumentWithReport(selectedFile.toPath());
            }

            @Override
            protected void done() {
                scanProgressBar.setVisible(false);
                chooseFileBtn.setEnabled(true);
                scanBtn.setEnabled(true);

                try {
                    currentScanReport = get();
                    currentMatches = new ArrayList<>(currentScanReport.getMatches());
                    updateExtractionSummaryUI(currentScanReport);
                    populateCandidateTable(currentMatches);
                    showPostScanNotification(currentScanReport);
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    scanOutcomeBadge.setText("EXTRACTION_FAILED");
                    scanOutcomeBadge.setForeground(ThemeManager.DANGER_RED);
                    pagesProcessedLabel.setText("0 processed");
                    pagesFailedLabel.setText("Failed");
                    pagesFailedLabel.setForeground(ThemeManager.DANGER_RED);
                    perPageStatusArea.setText("Extraction failed: " + cause.getMessage());
                    candidateCountLabel.setText("Extraction Failed (Cannot verify absence of sensitive data)");
                    DialogManager.showError(RedactionPanel.this, "Document Extraction Failure",
                            "Failed to extract content from document:\n" + cause.getMessage()
                                    + "\n\nNote: The engine never reports 'No sensitive content found' when extraction fails.");
                }
            }
        };

        worker.execute();
    }

    private void updateExtractionSummaryUI(DocumentScanReport report) {
        ScanOutcome outcome = report.getOutcome();
        scanOutcomeBadge.setText(outcome.name());
        switch (outcome) {
            case SUCCESS_WITH_MATCHES, SUCCESS_NO_MATCHES -> scanOutcomeBadge.setForeground(ThemeManager.SUCCESS_GREEN);
            case OCR_UNAVAILABLE, LOW_CONFIDENCE_OCR, PARTIAL_EXTRACTION_FAILURE -> scanOutcomeBadge.setForeground(ThemeManager.WARNING_AMBER);
            case EXTRACTION_FAILED -> scanOutcomeBadge.setForeground(ThemeManager.DANGER_RED);
        }

        pagesProcessedLabel.setText(report.getPagesProcessed() + " / " + report.getTotalPages()
                + " (Native: " + report.getNativeTextPages()
                + ", OCR: " + report.getOcrPages() + ")");

        int failed = report.getPagesFailed();
        pagesFailedLabel.setText(String.valueOf(failed));
        pagesFailedLabel.setForeground(failed > 0 ? ThemeManager.DANGER_RED : ThemeManager.SUCCESS_GREEN);

        ocrStatusLabel.setText(report.isOcrAvailable()
                ? "Available (" + context.getApplicationConfig().getOcrLanguage() + ")"
                : "Unavailable (See Setup Guide)");
        ocrStatusLabel.setForeground(report.isOcrAvailable() ? ThemeManager.SUCCESS_GREEN : ThemeManager.WARNING_AMBER);

        StringBuilder sb = new StringBuilder();
        sb.append(report.getSummaryMessage()).append("\n");
        for (PageExtractionReport pr : report.getPageReports()) {
            sb.append(String.format("  • Page %d [%s]: extractedChars=%d, ocrConf=%d%%%s — %s%n",
                    pr.getPageNumber(),
                    pr.getStatus().name(),
                    pr.getExtractedCharCount(),
                    pr.isOcrAttempted() && pr.getOcrConfidence() >= 0
                            ? (int) Math.round(pr.getOcrConfidence() * 100.0)
                            : 100,
                    pr.getStatus() == PageExtractionReport.PageStatus.LOW_CONFIDENCE_OCR ? " [MANUAL REVIEW]" : "",
                    pr.getDiagnosticMessage()));
        }
        perPageStatusArea.setText(sb.toString().trim());
        perPageStatusArea.setCaretPosition(0);
    }

    private void populateCandidateTable(List<RedactionMatch> matches) {
        suppressTableListener = true;
        candidateTableModel.setRowCount(0);

        for (RedactionMatch m : matches) {
            String statusPrefix = switch (m.getRedactionStatus()) {
                case REDACTABLE -> "[READY] ";
                case MANUAL_REVIEW_REQUIRED -> "[MANUAL REVIEW] ";
                case UNMAPPED_UNSAFE -> "[UNMAPPED - UNSAFE] ";
            };
            String methodAndConf = m.getDetectionMethod().name() + " (" + (int) Math.round(m.getConfidence() * 100) + "%)";
            candidateTableModel.addRow(new Object[]{
                    m.isSelectedForRedaction(),
                    m.getCandidateType(),
                    m.getMaskedPreview(),
                    m.getFormattedLocation(),
                    methodAndConf,
                    statusPrefix + m.getDetectionReason()
            });
        }
        suppressTableListener = false;

        boolean hasMatches = !matches.isEmpty();
        selectAllBtn.setEnabled(hasMatches);
        selectHighConfBtn.setEnabled(hasMatches);
        deselectAllBtn.setEnabled(hasMatches);
        updateSelectedCount();
    }

    private void showPostScanNotification(DocumentScanReport report) {
        ScanOutcome outcome = report.getOutcome();
        int matchCount = report.getMatches().size();

        if (outcome == ScanOutcome.OCR_UNAVAILABLE) {
            candidateCountLabel.setText(matchCount == 0
                    ? "OCR Unavailable — Scanned pages could not be inspected"
                    : matchCount + " candidate(s) on native pages (Scanned pages uninspected: OCR Unavailable)");
            DialogManager.showWarning(this, "OCR Unavailable for Scanned Page(s)",
                    report.getSummaryMessage()
                            + "<br><br>Click <b>OCR Setup Instructions</b> in Step 2 to configure local Tesseract OCR.");
        } else if (outcome == ScanOutcome.PARTIAL_EXTRACTION_FAILURE) {
            candidateCountLabel.setText(matchCount + " candidate(s) (" + report.getPagesFailed() + " page(s) failed extraction)");
            DialogManager.showWarning(this, "Partial Extraction Warning",
                    report.getSummaryMessage()
                            + "<br><br>Warning: Pages that failed extraction could not be verified as free of sensitive content.");
        } else if (outcome == ScanOutcome.LOW_CONFIDENCE_OCR) {
            DialogManager.showWarning(this, "Low-Confidence OCR Warning",
                    report.getSummaryMessage()
                            + "<br><br>Please carefully review all flagged OCR candidates before applying redactions.");
        } else if (outcome == ScanOutcome.SUCCESS_NO_MATCHES) {
            candidateCountLabel.setText("Extraction Succeeded — 0 sensitive candidates found");
            DialogManager.showInfo(this, "Scan Complete (No Matches)",
                    "All " + report.getPagesProcessed() + " page(s) were successfully extracted and analyzed. "
                            + "No sensitive PII or targeted patterns were detected.");
        }
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

    private void setCandidatesSelected(boolean selected, boolean highConfidenceOnly) {
        suppressTableListener = true;
        for (int i = 0; i < currentMatches.size(); i++) {
            RedactionMatch m = currentMatches.get(i);
            boolean shouldSelect = false;
            if (selected && m.canBeSafelyRedacted()) {
                shouldSelect = !highConfidenceOnly || !m.requiresManualReview();
            }
            m.setSelectedForRedaction(shouldSelect);
            candidateTableModel.setValueAt(shouldSelect, i, 0);
        }
        suppressTableListener = false;
        updateSelectedCount();
    }

    private void updateSelectedCount() {
        if (currentMatches.isEmpty()) {
            if (currentScanReport != null && currentScanReport.getOutcome() != ScanOutcome.SUCCESS_NO_MATCHES) {
                candidateCountLabel.setText("0 selected (" + currentScanReport.getOutcome().name() + ")");
            } else {
                candidateCountLabel.setText("0 candidates detected");
            }
            applyRedactionBtn.setEnabled(false);
            return;
        }
        int selectedCount = 0;
        int manualReviewSelected = 0;
        for (RedactionMatch m : currentMatches) {
            if (m.isSelectedForRedaction()) {
                selectedCount++;
                if (m.requiresManualReview()) {
                    manualReviewSelected++;
                }
            }
        }
        String reviewNote = manualReviewSelected > 0 ? " (" + manualReviewSelected + " flagged for manual review)" : "";
        candidateCountLabel.setText(selectedCount + " of " + currentMatches.size() + " selected for redaction" + reviewNote);
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
        long reviewCount = currentMatches.stream()
                .filter(m -> m.isSelectedForRedaction() && m.requiresManualReview())
                .count();
        String reviewPrompt = reviewCount > 0
                ? "\n\nNote: " + reviewCount + " selected item(s) were flagged for manual review."
                : "";

        boolean confirm = DialogManager.showConfirmation(this, "Confirm Permanent Redaction",
                "Permanently redact " + approvedCount + " selected item(s) and write sanitized output to:\n"
                        + outFile.getName() + reviewPrompt
                        + "\n\nThe original source file will never be modified.",
                "Apply Permanent Redaction");
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
        scanProgressBar.setVisible(true);
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
                scanProgressBar.setVisible(false);
                applyRedactionBtn.setEnabled(true);
                try {
                    RedactionResult result = get();
                    if (result.isSuccess()) {
                        context.setLastRedactedDocumentPath(result.getOutputPath());
                        if (signaturePathCreated != null) {
                            context.setLastSignaturePath(signaturePathCreated);
                        }

                        resultCard.setVisible(true);
                        resultStatusLabel.setText("Execution Status: Permanent Redaction Succeeded");
                        resultStatusLabel.setForeground(ThemeManager.SUCCESS_GREEN);

                        VerificationStatus vStatus = result.getVerificationStatus();
                        resultVerificationStatusLabel.setText("Final Verification Status: " + vStatus.name());
                        if (vStatus == VerificationStatus.VERIFIED) {
                            resultVerificationStatusLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                        } else if (vStatus == VerificationStatus.PARTIAL) {
                            resultVerificationStatusLabel.setForeground(ThemeManager.WARNING_AMBER);
                        } else {
                            resultVerificationStatusLabel.setForeground(ThemeManager.DANGER_RED);
                        }

                        resultOutputLocationLabel.setText("Output File Path: " + result.getOutputPath().toAbsolutePath());
                        resultCountLabel.setText(String.format(
                                "Detected: %d  |  Selected: %d  |  Redacted: %d  |  Skipped: %d  |  Failed: %d",
                                result.getTotalCandidatesConsidered(),
                                result.getSelectedMatchesCount(),
                                result.getApprovedMatchesApplied(),
                                result.getSkippedMatchesCount(),
                                result.getFailedMatchesCount()));
                        resultVerificationReportLabel.setText("<html><body style='width: 680px;'>"
                                + result.getVerificationReport() + "</body></html>");
                        resultHashesLabel.setText("<html>Source SHA-256: <code>" + result.getSourceSha256()
                                + "</code><br>Output SHA-256: <code>" + result.getOutputSha256() + "</code></html>");

                        if (signaturePathCreated != null) {
                            resultSignatureLabel.setText("Signature: Detached .zksig created for redacted output at "
                                    + signaturePathCreated.toAbsolutePath());
                            resultSignatureLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                        } else {
                            resultSignatureLabel.setText("Signature: Not digitally signed");
                            resultSignatureLabel.setForeground(ThemeManager.TEXT_SECONDARY);
                        }

                        DialogManager.showInfo(RedactionPanel.this, "Redaction & Verification Complete",
                                "Sanitized document saved to:\n" + result.getOutputPath().toAbsolutePath()
                                        + "\n\nIndependent Verification Status: " + vStatus.name()
                                        + "\nRedacted: " + result.getApprovedMatchesApplied()
                                        + " | Skipped: " + result.getSkippedMatchesCount()
                                        + (signaturePathCreated != null ? "\nDetached signature generated." : ""));
                    } else {
                        DialogManager.showError(RedactionPanel.this, "Redaction Failed", result.getSummaryMessage());
                    }
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    DialogManager.showError(RedactionPanel.this, "Redaction Execution Error",
                            "Failed to apply redactions safely:\n" + cause.getMessage());
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
